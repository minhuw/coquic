use std::{
    cell::RefCell,
    collections::{HashMap, VecDeque},
    env,
    error::Error,
    fs::File,
    io::Write,
    net::{SocketAddr, ToSocketAddrs, UdpSocket as StdUdpSocket},
    path::PathBuf,
    rc::Rc,
    time::{Duration, Instant},
};

use futures::{stream::FuturesUnordered, StreamExt};
use neqo_common::{event::Provider, Datagram, Tos};
use neqo_transport::CongestionControl;
use neqo_transport::{
    server::Server, Connection, ConnectionEvent, ConnectionIdGenerator, ConnectionParameters,
    EmptyConnectionIdGenerator, Output, RandomConnectionIdGenerator, State, StreamId, StreamType,
    Version,
};
use nss::{init, init_db, AllowZeroRtt, AntiReplay, AuthenticationStatus};
use tokio::{net::UdpSocket, time};

const APPLICATION_PROTOCOL: &str = "coquic-perf/1";
const PERF_PROTOCOL_VERSION: u32 = 3;
const CONTROL_STREAM_ID: u64 = 0;
const MESSAGE_SESSION_START: u8 = 1;
const MESSAGE_SESSION_READY: u8 = 2;
const MESSAGE_SESSION_ERROR: u8 = 3;
const MESSAGE_SESSION_COMPLETE: u8 = 4;
const MODE_CODE_BULK: u8 = 0;
const MODE_CODE_RR: u8 = 1;
const MODE_CODE_CRR: u8 = 2;
const MODE_CODE_PERSISTENT_RR: u8 = 3;
const DIRECTION_CODE_UPLOAD: u8 = 0;
const DIRECTION_CODE_DOWNLOAD: u8 = 1;
const DEFAULT_MAX_RUN_REQUESTS: u64 = 4096;
const TRANSFER_CONNECTION_WINDOW: u64 = 32 * 1024 * 1024;
const TRANSFER_STREAM_WINDOW: u64 = 16 * 1024 * 1024;
const TRANSFER_MAX_STREAMS: u64 = 1_000_000;
const WRITE_CHUNK_SIZE: usize = 1024;
const READ_BUF_SIZE: usize = 65_536;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const BATCH_TIMEOUT: Duration = Duration::from_secs(120);
const DRAIN_TIMEOUT: Duration = Duration::from_secs(2);
const SERVER_POLL: Duration = Duration::from_millis(10);
const DEFAULT_WAIT: Duration = Duration::from_millis(100);
const ANTI_REPLAY_WINDOW: Duration = Duration::from_secs(10);

type AnyError = Box<dyn Error>;

#[derive(Clone, Copy, Default)]
struct OptionalU64 {
    value: u64,
    set: bool,
}

#[derive(Clone)]
struct Config {
    role: String,
    host: String,
    port: u16,
    server_name: String,
    verify_peer: bool,
    io_backend: String,
    congestion_control: String,
    certificate_chain: String,
    private_key: String,
    disable_pmtud: bool,
    mode: String,
    direction: String,
    request_bytes: u64,
    response_bytes: u64,
    streams: u64,
    connections: u64,
    requests_in_flight: u64,
    requests: OptionalU64,
    total_bytes: OptionalU64,
    warmup: Duration,
    duration: Duration,
    json_out: Option<String>,
    neqo_db: PathBuf,
    neqo_key: String,
}

impl Config {
    fn defaults(role: String) -> Self {
        let neqo_db = env::var_os("NEQO_PERF_DB")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/usr/local/libexec/neqo-perf/db"));
        let neqo_key = env::var("NEQO_PERF_KEY").unwrap_or_else(|_| "key".to_string());
        Self {
            role,
            host: "127.0.0.1".to_string(),
            port: 4433,
            server_name: "localhost".to_string(),
            verify_peer: false,
            io_backend: "socket".to_string(),
            congestion_control: "default".to_string(),
            certificate_chain: "tests/fixtures/quic-server-cert.pem".to_string(),
            private_key: "tests/fixtures/quic-server-key.pem".to_string(),
            disable_pmtud: true,
            mode: "bulk".to_string(),
            direction: "download".to_string(),
            request_bytes: 64,
            response_bytes: 64,
            streams: 1,
            connections: 1,
            requests_in_flight: 1,
            requests: OptionalU64::default(),
            total_bytes: OptionalU64::default(),
            warmup: Duration::ZERO,
            duration: Duration::from_secs(5),
            json_out: None,
            neqo_db,
            neqo_key,
        }
    }
}

#[derive(Default)]
struct Counters {
    bytes_sent: u64,
    bytes_received: u64,
    requests_completed: u64,
    skipped_setup_errors: u64,
    latencies: Vec<Duration>,
}

#[derive(Default)]
struct LatencySummary {
    min_us: u64,
    avg_us: u64,
    p50_us: u64,
    p90_us: u64,
    p99_us: u64,
    max_us: u64,
}

struct RunSummary<'a> {
    status: &'a str,
    failure_reason: Option<String>,
    cfg: &'a Config,
    elapsed_ms: u64,
    counters: Counters,
    latency: LatencySummary,
    throughput_mib_per_s: f64,
    throughput_gbit_per_s: f64,
    requests_per_s: f64,
}

#[derive(Clone, Copy)]
struct RequestShape {
    request_bytes: u64,
    response_bytes: u64,
    counts_latency: bool,
}

#[derive(Clone)]
struct SessionStart {
    mode: String,
    direction: String,
    request_bytes: u64,
    response_bytes: u64,
    total_bytes: OptionalU64,
    requests: OptionalU64,
    warmup: Duration,
    duration: Duration,
    streams: u64,
    connections: u64,
    requests_in_flight: u64,
}

#[derive(Default)]
struct ControlMessage {
    message_type: u8,
    ready: bool,
    error_reason: String,
    start: Option<SessionStart>,
}

struct ClientStream {
    request_bytes: u64,
    response_bytes: u64,
    request_sent: u64,
    response_received: u64,
    started_at: Instant,
    counts_latency: bool,
    send_closed: bool,
    response_fin: bool,
    counted: bool,
    persistent: bool,
    closing: bool,
    response_pending: u64,
    chunk_request_bytes: u64,
    outstanding: VecDeque<PersistentRequest>,
}

struct PersistentRequest {
    started_at: Instant,
}

struct ClientBatch {
    target_requests: u64,
    max_active_requests: Option<u64>,
    started_requests: u64,
    completed_requests: u64,
    shape: RequestShape,
    control_stream: Option<StreamId>,
    control_out: Vec<u8>,
    control_sent: usize,
    control_recv: Vec<u8>,
    control_closed: bool,
    session_ready: bool,
    streams: HashMap<StreamId, ClientStream>,
    persistent: bool,
    persistent_stream: Option<StreamId>,
}

impl ClientBatch {
    fn new(cfg: &Config, target_requests: u64, shape: RequestShape) -> Self {
        let max_active_requests = if cfg.mode == "rr" || cfg.mode == "persistent-rr" {
            Some(cfg.requests_in_flight.max(1))
        } else if cfg.mode == "bulk" && target_requests == u64::MAX {
            Some(cfg.streams.max(1))
        } else {
            None
        };
        Self {
            target_requests,
            max_active_requests,
            started_requests: 0,
            completed_requests: 0,
            shape,
            control_stream: None,
            control_out: encode_session_start(&make_session_start_from_shape(
                cfg,
                shape,
                if (cfg.mode == "rr" || cfg.mode == "persistent-rr") && target_requests != u64::MAX
                {
                    Some(target_requests)
                } else {
                    None
                },
            )),
            control_sent: 0,
            control_recv: Vec::new(),
            control_closed: false,
            session_ready: false,
            streams: HashMap::new(),
            persistent: cfg.mode == "persistent-rr",
            persistent_stream: None,
        }
    }

    fn is_done(&self) -> bool {
        self.completed_requests >= self.target_requests
    }

    fn active_requests(&self) -> u64 {
        self.started_requests - self.completed_requests
    }

    fn handle_events(
        &mut self,
        conn: &mut Connection,
        counters: &mut Counters,
    ) -> Result<(), String> {
        while let Some(event) = conn.next_event() {
            match event {
                ConnectionEvent::AuthenticationNeeded
                | ConnectionEvent::EchFallbackAuthenticationNeeded { .. } => {
                    if self.shape.counts_latency {
                        conn.authenticated(AuthenticationStatus::Ok, Instant::now());
                    } else {
                        conn.authenticated(AuthenticationStatus::Ok, Instant::now());
                    }
                }
                ConnectionEvent::StateChange(State::Connected)
                | ConnectionEvent::StateChange(State::Confirmed) => {
                    self.open_control(conn)?;
                    self.open_streams(conn)?;
                }
                ConnectionEvent::SendStreamCreatable {
                    stream_type: StreamType::BiDi,
                } => {
                    self.open_control(conn)?;
                    self.open_streams(conn)?;
                }
                ConnectionEvent::NewStream { .. } => {}
                ConnectionEvent::SendStreamWritable { stream_id } => {
                    self.write_stream(conn, stream_id)?;
                }
                ConnectionEvent::RecvStreamReadable { stream_id } => {
                    self.read_stream(conn, stream_id, counters)?;
                }
                ConnectionEvent::RecvStreamReset {
                    stream_id,
                    app_error,
                } => {
                    return Err(format!(
                        "neqo stream {stream_id} reset by peer with error {app_error}"
                    ));
                }
                ConnectionEvent::StateChange(State::Closed(reason))
                | ConnectionEvent::StateChange(State::Closing { error: reason, .. })
                | ConnectionEvent::StateChange(State::Draining { error: reason, .. }) => {
                    if !self.is_done() {
                        return Err(format!(
                            "neqo connection closed before batch completed: {reason:?}"
                        ));
                    }
                }
                ConnectionEvent::SendStreamComplete { .. }
                | ConnectionEvent::SendStreamCreatable { .. }
                | ConnectionEvent::SendStreamStopSending { .. }
                | ConnectionEvent::StateChange(_)
                | ConnectionEvent::ZeroRttRejected
                | ConnectionEvent::ResumptionToken(_)
                | ConnectionEvent::Datagram(_)
                | ConnectionEvent::OutgoingDatagramOutcome { .. }
                | ConnectionEvent::IncomingDatagramDropped
                | ConnectionEvent::SconeUpdated(_)
                | ConnectionEvent::PathMigrated { .. } => {}
            }
        }
        if conn.state().connected() {
            self.open_control(conn)?;
            self.open_streams(conn)?;
        }
        Ok(())
    }

    fn open_control(&mut self, conn: &mut Connection) -> Result<(), String> {
        if self.control_stream.is_some() {
            return Ok(());
        }
        match conn.stream_create(StreamType::BiDi) {
            Ok(stream_id) => {
                if stream_id.as_u64() != CONTROL_STREAM_ID {
                    return Err(format!("unexpected neqo control stream id: {stream_id}"));
                }
                self.control_stream = Some(stream_id);
                self.write_control(conn)?;
            }
            Err(neqo_transport::Error::StreamLimit)
            | Err(neqo_transport::Error::ConnectionState) => {}
            Err(err) => return Err(format!("neqo control stream_create failed: {err}")),
        }
        Ok(())
    }

    fn open_streams(&mut self, conn: &mut Connection) -> Result<(), String> {
        if !self.session_ready {
            return Ok(());
        }
        if self.persistent {
            return self.open_persistent_stream(conn);
        }
        while self.started_requests < self.target_requests {
            if let Some(max_active_requests) = self.max_active_requests {
                if self.active_requests() >= max_active_requests {
                    break;
                }
            }
            match conn.stream_create(StreamType::BiDi) {
                Ok(stream_id) => {
                    self.streams.insert(
                        stream_id,
                        ClientStream {
                            request_bytes: self.shape.request_bytes,
                            response_bytes: self.shape.response_bytes,
                            request_sent: 0,
                            response_received: 0,
                            started_at: Instant::now(),
                            counts_latency: self.shape.counts_latency,
                            send_closed: false,
                            response_fin: false,
                            counted: false,
                            persistent: false,
                            closing: false,
                            response_pending: 0,
                            chunk_request_bytes: self.shape.request_bytes,
                            outstanding: VecDeque::new(),
                        },
                    );
                    self.started_requests += 1;
                    self.write_stream(conn, stream_id)?;
                }
                Err(neqo_transport::Error::StreamLimit)
                | Err(neqo_transport::Error::ConnectionState) => break,
                Err(err) => {
                    return Err(format!("neqo stream_create failed: {err}"));
                }
            }
        }
        Ok(())
    }

    fn open_persistent_stream(&mut self, conn: &mut Connection) -> Result<(), String> {
        let stream_id = match self.persistent_stream {
            Some(stream_id) => stream_id,
            None => match conn.stream_create(StreamType::BiDi) {
                Ok(stream_id) => {
                    self.persistent_stream = Some(stream_id);
                    self.streams.insert(
                        stream_id,
                        ClientStream {
                            request_bytes: 0,
                            response_bytes: self.shape.response_bytes,
                            request_sent: 0,
                            response_received: 0,
                            started_at: Instant::now(),
                            counts_latency: self.shape.counts_latency,
                            send_closed: false,
                            response_fin: false,
                            counted: false,
                            persistent: true,
                            closing: false,
                            response_pending: 0,
                            chunk_request_bytes: self.shape.request_bytes,
                            outstanding: VecDeque::new(),
                        },
                    );
                    stream_id
                }
                Err(neqo_transport::Error::StreamLimit)
                | Err(neqo_transport::Error::ConnectionState) => return Ok(()),
                Err(err) => return Err(format!("neqo stream_create failed: {err}")),
            },
        };

        while self.started_requests < self.target_requests {
            if let Some(max_active_requests) = self.max_active_requests {
                if self.active_requests() >= max_active_requests {
                    break;
                }
            }
            let stream = self
                .streams
                .get_mut(&stream_id)
                .ok_or_else(|| "neqo persistent stream missing".to_string())?;
            stream.request_bytes += self.shape.request_bytes;
            stream.response_bytes = self.shape.response_bytes;
            stream.chunk_request_bytes = self.shape.request_bytes;
            stream.outstanding.push_back(PersistentRequest {
                started_at: Instant::now(),
            });
            self.started_requests += 1;
            self.write_stream(conn, stream_id)?;
        }
        Ok(())
    }

    fn write_stream(&mut self, conn: &mut Connection, stream_id: StreamId) -> Result<(), String> {
        if self.control_stream == Some(stream_id) {
            return self.write_control(conn);
        }
        let Some(stream) = self.streams.get_mut(&stream_id) else {
            return Ok(());
        };
        if stream.send_closed {
            return Ok(());
        }

        loop {
            if stream.request_sent < stream.request_bytes {
                let left = stream.request_bytes - stream.request_sent;
                let chunk = left.min(WRITE_CHUNK_SIZE as u64) as usize;
                let sent = conn
                    .stream_send(stream_id, &ZERO_CHUNK[..chunk])
                    .map_err(|err| format!("neqo stream_send body failed: {err}"))?;
                if sent == 0 {
                    return Ok(());
                }
                stream.request_sent += sent as u64;
                continue;
            }

            if stream.persistent && !stream.closing {
                return Ok(());
            }
            conn.stream_close_send(stream_id)
                .map_err(|err| format!("neqo stream_close_send failed: {err}"))?;
            stream.send_closed = true;
            return Ok(());
        }
    }

    fn write_control(&mut self, conn: &mut Connection) -> Result<(), String> {
        let Some(stream_id) = self.control_stream else {
            return Ok(());
        };
        if self.control_closed {
            return Ok(());
        }
        while self.control_sent < self.control_out.len() {
            let sent = conn
                .stream_send(stream_id, &self.control_out[self.control_sent..])
                .map_err(|err| format!("neqo control stream_send failed: {err}"))?;
            if sent == 0 {
                return Ok(());
            }
            self.control_sent += sent;
        }
        conn.stream_close_send(stream_id)
            .map_err(|err| format!("neqo control stream_close_send failed: {err}"))?;
        self.control_closed = true;
        Ok(())
    }

    fn read_stream(
        &mut self,
        conn: &mut Connection,
        stream_id: StreamId,
        counters: &mut Counters,
    ) -> Result<(), String> {
        if self.control_stream == Some(stream_id) {
            return self.read_control(conn, stream_id);
        }
        let Some(stream) = self.streams.get_mut(&stream_id) else {
            return Ok(());
        };

        let mut buf = [0u8; 8192];
        loop {
            let (read, fin) = match conn.stream_recv(stream_id, &mut buf) {
                Ok(result) => result,
                Err(neqo_transport::Error::NoMoreData) => break,
                Err(err) => return Err(format!("neqo stream_recv failed: {err}")),
            };
            if read > 0 {
                if stream.persistent {
                    stream.response_received += read as u64;
                    stream.response_pending += read as u64;
                    while stream.response_pending >= stream.response_bytes
                        && !stream.outstanding.is_empty()
                    {
                        stream.response_pending -= stream.response_bytes;
                        let request = stream.outstanding.pop_front().expect("checked non-empty");
                        counters.bytes_sent += stream.chunk_request_bytes;
                        counters.bytes_received += stream.response_bytes;
                        counters.requests_completed += 1;
                        self.completed_requests += 1;
                        if stream.counts_latency {
                            counters.latencies.push(request.started_at.elapsed());
                        }
                    }
                    continue;
                }
                stream.response_received += read as u64;
                if stream.response_received > stream.response_bytes {
                    return Err(format!(
                        "neqo response byte count mismatch: got more than {}, expected {}",
                        stream.response_received, stream.response_bytes
                    ));
                }
            }
            if fin {
                stream.response_fin = true;
                break;
            }
            if read == 0 {
                break;
            }
        }

        if stream.persistent {
            return Ok(());
        }
        if stream.response_fin && !stream.counted {
            if stream.response_received != stream.response_bytes {
                return Err(format!(
                    "neqo response byte count mismatch: got {}, expected {}",
                    stream.response_received, stream.response_bytes
                ));
            }
            stream.counted = true;
            counters.bytes_sent += stream.request_bytes;
            counters.bytes_received += stream.response_bytes;
            counters.requests_completed += 1;
            self.completed_requests += 1;
            if stream.counts_latency {
                counters.latencies.push(stream.started_at.elapsed());
            }
        }
        Ok(())
    }

    fn read_control(&mut self, conn: &mut Connection, stream_id: StreamId) -> Result<(), String> {
        let mut buf = [0u8; 1024];
        loop {
            let (read, fin) = match conn.stream_recv(stream_id, &mut buf) {
                Ok(result) => result,
                Err(neqo_transport::Error::NoMoreData) => break,
                Err(err) => return Err(format!("neqo control stream_recv failed: {err}")),
            };
            if read > 0 {
                self.control_recv.extend_from_slice(&buf[..read]);
            }
            if fin || read == 0 {
                break;
            }
        }
        if self.control_recv.len() >= 5 {
            let payload_len =
                u32::from_be_bytes(self.control_recv[1..5].try_into().unwrap()) as usize;
            if self.control_recv.len() >= payload_len + 5 {
                let msg = decode_control_message(&self.control_recv)?;
                match msg.message_type {
                    MESSAGE_SESSION_READY if msg.ready => {
                        self.session_ready = true;
                        self.open_streams(conn)?;
                    }
                    MESSAGE_SESSION_ERROR => {
                        return Err(format!("neqo server session_error: {}", msg.error_reason));
                    }
                    MESSAGE_SESSION_COMPLETE => {}
                    _ => return Err("unexpected neqo control message".to_string()),
                }
            }
        }
        Ok(())
    }

    fn close_persistent_streams(&mut self, conn: &mut Connection) -> Result<(), String> {
        let Some(stream_id) = self.persistent_stream else {
            return Ok(());
        };
        if let Some(stream) = self.streams.get_mut(&stream_id) {
            stream.closing = true;
        }
        self.write_stream(conn, stream_id)
    }
}

#[derive(Default)]
struct ServerStream {
    request_bytes: u64,
    response_bytes: u64,
    request_received: u64,
    response_sent: u64,
    writable: bool,
    ready_to_send: bool,
    send_closed: bool,
    shape_set: bool,
    persistent: bool,
    request_fin: bool,
}

#[derive(Default)]
struct ServerConnState {
    session: Option<SessionStart>,
    control_recv: Vec<u8>,
    control_out: Vec<u8>,
    control_sent: usize,
    control_fin: bool,
    streams: HashMap<StreamId, ServerStream>,
}

struct PerfServer {
    server: Server,
    conns: HashMap<neqo_transport::server::ConnectionRef, ServerConnState>,
}

impl PerfServer {
    fn new(cfg: &Config) -> Result<Self, AnyError> {
        init_db(cfg.neqo_db.clone())?;
        let params = connection_params(cfg);
        let anti_replay = AntiReplay::new(Instant::now(), ANTI_REPLAY_WINDOW, 7, 14)?;
        let cid_mgr: Rc<RefCell<dyn ConnectionIdGenerator>> =
            Rc::new(RefCell::new(RandomConnectionIdGenerator::new(10)));
        let server = Server::new(
            Instant::now(),
            &[cfg.neqo_key.clone()],
            &[APPLICATION_PROTOCOL],
            anti_replay,
            Box::new(AllowZeroRtt {}),
            cid_mgr,
            params,
        )?;
        Ok(Self {
            server,
            conns: HashMap::new(),
        })
    }

    fn process(&mut self, dgram: Option<Datagram>, now: Instant) -> Output {
        self.server.process(dgram, now)
    }

    fn process_events(&mut self) -> Result<(), String> {
        #[allow(clippy::mutable_key_type)]
        let active = self.server.active_connections();
        for conn_ref in active {
            self.conns.entry(conn_ref.clone()).or_default();
            loop {
                let event = match conn_ref.borrow_mut().next_event() {
                    Some(event) => event,
                    None => break,
                };
                match event {
                    ConnectionEvent::NewStream { stream_id } => {
                        let conn_state = self.conns.entry(conn_ref.clone()).or_default();
                        if stream_id.as_u64() != CONTROL_STREAM_ID {
                            conn_state.streams.entry(stream_id).or_default();
                        }
                    }
                    ConnectionEvent::RecvStreamReadable { stream_id } => {
                        self.read_stream(stream_id, &conn_ref)?;
                        self.write_stream(stream_id, &conn_ref)?;
                    }
                    ConnectionEvent::SendStreamWritable { stream_id } => {
                        if stream_id.as_u64() == CONTROL_STREAM_ID {
                            // control writability is handled below
                        } else {
                            self.conns
                                .entry(conn_ref.clone())
                                .or_default()
                                .streams
                                .entry(stream_id)
                                .or_default()
                                .writable = true;
                        }
                        self.write_stream(stream_id, &conn_ref)?;
                    }
                    ConnectionEvent::RecvStreamReset { stream_id, .. }
                    | ConnectionEvent::SendStreamComplete { stream_id }
                    | ConnectionEvent::SendStreamStopSending { stream_id, .. } => {
                        if let Some(conn_state) = self.conns.get_mut(&conn_ref) {
                            conn_state.streams.remove(&stream_id);
                        }
                    }
                    ConnectionEvent::StateChange(State::Connected)
                    | ConnectionEvent::StateChange(State::Confirmed)
                    | ConnectionEvent::StateChange(_)
                    | ConnectionEvent::SendStreamCreatable { .. }
                    | ConnectionEvent::ZeroRttRejected
                    | ConnectionEvent::ResumptionToken(_)
                    | ConnectionEvent::Datagram(_)
                    | ConnectionEvent::OutgoingDatagramOutcome { .. }
                    | ConnectionEvent::IncomingDatagramDropped
                    | ConnectionEvent::AuthenticationNeeded
                    | ConnectionEvent::EchFallbackAuthenticationNeeded { .. }
                    | ConnectionEvent::SconeUpdated(_)
                    | ConnectionEvent::PathMigrated { .. } => {}
                }
            }
        }
        Ok(())
    }

    fn read_stream(
        &mut self,
        stream_id: StreamId,
        conn_ref: &neqo_transport::server::ConnectionRef,
    ) -> Result<(), String> {
        if stream_id.as_u64() == CONTROL_STREAM_ID {
            return self.read_control(stream_id, conn_ref);
        }
        let conn_state = self.conns.entry(conn_ref.clone()).or_default();
        let Some(session) = conn_state.session.clone() else {
            return Err("neqo data stream opened before session_start".to_string());
        };
        let stream = conn_state.streams.entry(stream_id).or_default();
        if !stream.shape_set {
            stream.request_bytes = session.request_bytes;
            stream.response_bytes = if session.mode == "persistent-rr" {
                0
            } else {
                session.response_bytes
            };
            stream.persistent = session.mode == "persistent-rr";
            stream.shape_set = true;
        }
        let mut buf = [0u8; 8192];
        loop {
            let (read, fin) = match conn_ref.borrow_mut().stream_recv(stream_id, &mut buf) {
                Ok(result) => result,
                Err(neqo_transport::Error::NoMoreData) => break,
                Err(err) => return Err(format!("neqo server stream_recv failed: {err}")),
            };
            if read == 0 && !fin {
                break;
            }

            stream.request_received += read as u64;
            if stream.persistent {
                while stream.request_received >= stream.request_bytes {
                    stream.request_received -= stream.request_bytes;
                    stream.response_bytes =
                        stream.response_bytes.saturating_add(session.response_bytes);
                    stream.ready_to_send = true;
                }
                if fin {
                    if stream.request_received != 0 {
                        return Err(
                            "neqo persistent-rr stream ended with partial request".to_string()
                        );
                    }
                    stream.request_fin = true;
                    stream.ready_to_send = true;
                }
            } else {
                if stream.request_received >= stream.request_bytes {
                    stream.ready_to_send = true;
                }
                if fin && stream.request_received >= stream.request_bytes {
                    stream.ready_to_send = true;
                }
            }
            if read == 0 {
                break;
            }
        }
        Ok(())
    }

    fn read_control(
        &mut self,
        stream_id: StreamId,
        conn_ref: &neqo_transport::server::ConnectionRef,
    ) -> Result<(), String> {
        let conn_state = self.conns.entry(conn_ref.clone()).or_default();
        let mut buf = [0u8; 1024];
        loop {
            let (read, fin) = match conn_ref.borrow_mut().stream_recv(stream_id, &mut buf) {
                Ok(result) => result,
                Err(neqo_transport::Error::NoMoreData) => break,
                Err(err) => return Err(format!("neqo server control stream_recv failed: {err}")),
            };
            if read > 0 {
                conn_state.control_recv.extend_from_slice(&buf[..read]);
            }
            if fin || read == 0 {
                break;
            }
        }
        if conn_state.control_recv.len() >= 5 {
            let payload_len =
                u32::from_be_bytes(conn_state.control_recv[1..5].try_into().unwrap()) as usize;
            if conn_state.control_recv.len() >= payload_len + 5 {
                match decode_control_message(&conn_state.control_recv) {
                    Ok(msg) if msg.message_type == MESSAGE_SESSION_START => {
                        conn_state.session = msg.start;
                        conn_state.control_out = encode_session_ready();
                        conn_state.control_sent = 0;
                        conn_state.control_fin = false;
                    }
                    Ok(_) | Err(_) => {
                        conn_state.control_out = encode_session_error("invalid session_start");
                        conn_state.control_sent = 0;
                        conn_state.control_fin = true;
                    }
                }
                self.write_control(stream_id, conn_ref)?;
            }
        }
        Ok(())
    }

    fn write_stream(
        &mut self,
        stream_id: StreamId,
        conn_ref: &neqo_transport::server::ConnectionRef,
    ) -> Result<(), String> {
        if stream_id.as_u64() == CONTROL_STREAM_ID {
            return self.write_control(stream_id, conn_ref);
        }
        let Some(conn_state) = self.conns.get_mut(conn_ref) else {
            return Ok(());
        };
        let Some(stream) = conn_state.streams.get_mut(&stream_id) else {
            return Ok(());
        };
        if !stream.ready_to_send || !stream.writable || stream.send_closed {
            return Ok(());
        }

        loop {
            if stream.response_sent < stream.response_bytes {
                let left = stream.response_bytes - stream.response_sent;
                let chunk = left.min(WRITE_CHUNK_SIZE as u64) as usize;
                let sent = conn_ref
                    .borrow_mut()
                    .stream_send(stream_id, &ZERO_CHUNK[..chunk])
                    .map_err(|err| format!("neqo server stream_send failed: {err}"))?;
                if sent == 0 {
                    stream.writable = false;
                    return Ok(());
                }
                stream.response_sent += sent as u64;
                continue;
            }

            if stream.persistent && !stream.request_fin {
                stream.ready_to_send = false;
                return Ok(());
            }
            conn_ref
                .borrow_mut()
                .stream_close_send(stream_id)
                .map_err(|err| format!("neqo server stream_close_send failed: {err}"))?;
            stream.send_closed = true;
            conn_state.streams.remove(&stream_id);
            return Ok(());
        }
    }

    fn write_control(
        &mut self,
        stream_id: StreamId,
        conn_ref: &neqo_transport::server::ConnectionRef,
    ) -> Result<(), String> {
        let Some(conn_state) = self.conns.get_mut(conn_ref) else {
            return Ok(());
        };
        if conn_state.control_out.is_empty() {
            return Ok(());
        }
        while conn_state.control_sent < conn_state.control_out.len() {
            let sent = conn_ref
                .borrow_mut()
                .stream_send(
                    stream_id,
                    &conn_state.control_out[conn_state.control_sent..],
                )
                .map_err(|err| format!("neqo server control stream_send failed: {err}"))?;
            if sent == 0 {
                return Ok(());
            }
            conn_state.control_sent += sent;
        }
        if conn_state.control_fin {
            conn_ref
                .borrow_mut()
                .stream_close_send(stream_id)
                .map_err(|err| format!("neqo server control stream_close_send failed: {err}"))?;
        }
        Ok(())
    }
}

static ZERO_CHUNK: [u8; WRITE_CHUNK_SIZE] = [0; WRITE_CHUNK_SIZE];

fn parse_args() -> Result<Config, String> {
    let mut args: Vec<String> = env::args().collect();
    if args.len() < 2 || (args[1] != "client" && args[1] != "server") {
        return Err("usage: neqo-perf [client|server] [options]".to_string());
    }
    let mut cfg = Config::defaults(args.remove(1));

    let mut i = 1;
    while i < args.len() {
        let arg = &args[i];
        match arg.as_str() {
            "--verify-peer" => {
                cfg.verify_peer = true;
                i += 1;
            }
            "--disable-pmtud" => {
                cfg.disable_pmtud = true;
                i += 1;
            }
            "--host" => {
                cfg.host = take_value(&args, &mut i, arg)?;
            }
            "--port" => {
                cfg.port = parse_u16(&take_value(&args, &mut i, arg)?, arg)?;
            }
            "--server-name" => {
                cfg.server_name = take_value(&args, &mut i, arg)?;
            }
            "--io-backend" => {
                cfg.io_backend = take_value(&args, &mut i, arg)?;
            }
            "--congestion-control" => {
                cfg.congestion_control = take_value(&args, &mut i, arg)?;
            }
            "--certificate-chain" => {
                cfg.certificate_chain = take_value(&args, &mut i, arg)?;
            }
            "--private-key" => {
                cfg.private_key = take_value(&args, &mut i, arg)?;
            }
            "--mode" => {
                cfg.mode = take_value(&args, &mut i, arg)?;
            }
            "--direction" => {
                cfg.direction = take_value(&args, &mut i, arg)?;
            }
            "--request-bytes" => {
                cfg.request_bytes = parse_u64(&take_value(&args, &mut i, arg)?, arg)?;
            }
            "--response-bytes" => {
                cfg.response_bytes = parse_u64(&take_value(&args, &mut i, arg)?, arg)?;
            }
            "--streams" => {
                cfg.streams = parse_u64(&take_value(&args, &mut i, arg)?, arg)?;
            }
            "--connections" => {
                cfg.connections = parse_u64(&take_value(&args, &mut i, arg)?, arg)?;
            }
            "--requests-in-flight" => {
                cfg.requests_in_flight = parse_u64(&take_value(&args, &mut i, arg)?, arg)?;
            }
            "--requests" => {
                cfg.requests = OptionalU64 {
                    value: parse_u64(&take_value(&args, &mut i, arg)?, arg)?,
                    set: true,
                };
            }
            "--total-bytes" => {
                cfg.total_bytes = OptionalU64 {
                    value: parse_u64(&take_value(&args, &mut i, arg)?, arg)?,
                    set: true,
                };
            }
            "--warmup" => {
                cfg.warmup = parse_duration(&take_value(&args, &mut i, arg)?)?;
            }
            "--duration" => {
                cfg.duration = parse_duration(&take_value(&args, &mut i, arg)?)?;
            }
            "--json-out" => {
                cfg.json_out = Some(take_value(&args, &mut i, arg)?);
            }
            unknown => {
                return Err(format!("unknown argument: {unknown}"));
            }
        }
    }

    validate_config(&cfg)?;
    Ok(cfg)
}

fn take_value(args: &[String], i: &mut usize, arg: &str) -> Result<String, String> {
    *i += 1;
    if *i >= args.len() {
        return Err(format!("missing value for {arg}"));
    }
    let value = args[*i].clone();
    *i += 1;
    Ok(value)
}

fn parse_u64(text: &str, name: &str) -> Result<u64, String> {
    text.parse().map_err(|_| format!("invalid {name}: {text}"))
}

fn parse_u16(text: &str, name: &str) -> Result<u16, String> {
    text.parse().map_err(|_| format!("invalid {name}: {text}"))
}

fn parse_duration(text: &str) -> Result<Duration, String> {
    if let Some(ms) = text.strip_suffix("ms") {
        return Ok(Duration::from_millis(parse_u64(ms, "duration")?));
    }
    if let Some(s) = text.strip_suffix('s') {
        return Ok(Duration::from_secs(parse_u64(s, "duration")?));
    }
    Err(format!("invalid duration: {text}"))
}

fn validate_config(cfg: &Config) -> Result<(), String> {
    if cfg.mode != "bulk" && cfg.mode != "rr" && cfg.mode != "crr" && cfg.mode != "persistent-rr" {
        return Err(format!("unsupported mode: {}", cfg.mode));
    }
    if cfg.io_backend != "socket" {
        return Err("neqo-perf only supports the socket backend".to_string());
    }
    match cfg.congestion_control.as_str() {
        "default" | "newreno" | "reno" | "cubic" => {}
        "bbr" | "copa" => {
            return Err(
                "neqo-perf does not provide BBR or Copa; use PERF_CONGESTION_CONTROLS=default"
                    .to_string(),
            );
        }
        other => return Err(format!("unsupported congestion-control label: {other}")),
    }
    if cfg.direction != "upload" && cfg.direction != "download" && cfg.direction != "stay" {
        return Err(format!("unsupported direction: {}", cfg.direction));
    }
    if cfg.streams == 0 || cfg.connections == 0 || cfg.requests_in_flight == 0 {
        return Err(
            "streams, connections, and requests-in-flight must be greater than zero".to_string(),
        );
    }
    if cfg.mode == "persistent-rr" && (cfg.request_bytes == 0 || cfg.response_bytes == 0) {
        return Err("persistent-rr requires nonzero request and response bytes".to_string());
    }
    Ok(())
}

fn neqo_cc(label: &str) -> CongestionControl {
    match label {
        "cubic" => CongestionControl::Cubic,
        _ => CongestionControl::NewReno,
    }
}

fn connection_params(cfg: &Config) -> ConnectionParameters {
    ConnectionParameters::default()
        .versions(Version::Version1, vec![Version::Version1])
        .max_data(TRANSFER_CONNECTION_WINDOW)
        .max_stream_data(StreamType::BiDi, false, TRANSFER_STREAM_WINDOW)
        .max_stream_data(StreamType::BiDi, true, TRANSFER_STREAM_WINDOW)
        .max_stream_data(StreamType::UniDi, true, TRANSFER_STREAM_WINDOW)
        .max_streams(StreamType::BiDi, TRANSFER_MAX_STREAMS)
        .max_streams(StreamType::UniDi, 0)
        .idle_timeout(Duration::from_secs(30))
        .congestion_control(neqo_cc(&cfg.congestion_control))
        .pmtud(!cfg.disable_pmtud)
}

fn resolve_remote(host: &str, port: u16) -> Result<SocketAddr, AnyError> {
    let mut addrs = (host, port).to_socket_addrs()?;
    addrs
        .next()
        .ok_or_else(|| format!("could not resolve {host}:{port}").into())
}

fn bind_addr_for(remote: SocketAddr) -> SocketAddr {
    if remote.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    }
}

fn mode_code(mode: &str) -> u8 {
    match mode {
        "rr" => MODE_CODE_RR,
        "crr" => MODE_CODE_CRR,
        "persistent-rr" => MODE_CODE_PERSISTENT_RR,
        _ => MODE_CODE_BULK,
    }
}

fn direction_code(direction: &str) -> u8 {
    if direction == "upload" {
        DIRECTION_CODE_UPLOAD
    } else {
        DIRECTION_CODE_DOWNLOAD
    }
}

fn make_session_start_from_shape(
    cfg: &Config,
    shape: RequestShape,
    request_limit: Option<u64>,
) -> SessionStart {
    SessionStart {
        mode: cfg.mode.clone(),
        direction: cfg.direction.clone(),
        request_bytes: shape.request_bytes,
        response_bytes: shape.response_bytes,
        total_bytes: cfg.total_bytes,
        requests: request_limit
            .map(|value| OptionalU64 { value, set: true })
            .unwrap_or(cfg.requests),
        warmup: cfg.warmup,
        duration: cfg.duration,
        streams: cfg.streams,
        connections: cfg.connections,
        requests_in_flight: cfg.requests_in_flight,
    }
}

fn encode_session_start(start: &SessionStart) -> Vec<u8> {
    let mut payload = Vec::with_capacity(79);
    payload.extend_from_slice(&PERF_PROTOCOL_VERSION.to_be_bytes());
    payload.push(mode_code(&start.mode));
    payload.push(direction_code(&start.direction));
    payload.extend_from_slice(&start.request_bytes.to_be_bytes());
    payload.extend_from_slice(&start.response_bytes.to_be_bytes());
    payload.push(
        (if start.total_bytes.set { 0x01 } else { 0 })
            | (if start.requests.set { 0x02 } else { 0 }),
    );
    payload.extend_from_slice(&start.total_bytes.value.to_be_bytes());
    payload.extend_from_slice(&start.requests.value.to_be_bytes());
    payload.extend_from_slice(&(start.warmup.as_micros() as u64).to_be_bytes());
    payload.extend_from_slice(&(start.duration.as_micros() as u64).to_be_bytes());
    payload.extend_from_slice(&start.streams.to_be_bytes());
    payload.extend_from_slice(&start.connections.to_be_bytes());
    payload.extend_from_slice(&start.requests_in_flight.to_be_bytes());
    frame_control_message(MESSAGE_SESSION_START, &payload)
}

fn frame_control_message(message_type: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + payload.len());
    out.push(message_type);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

fn encode_session_ready() -> Vec<u8> {
    frame_control_message(MESSAGE_SESSION_READY, &PERF_PROTOCOL_VERSION.to_be_bytes())
}

fn encode_session_error(reason: &str) -> Vec<u8> {
    let mut payload = Vec::with_capacity(4 + reason.len());
    payload.extend_from_slice(&(reason.len() as u32).to_be_bytes());
    payload.extend_from_slice(reason.as_bytes());
    frame_control_message(MESSAGE_SESSION_ERROR, &payload)
}

fn decode_control_message(data: &[u8]) -> Result<ControlMessage, String> {
    if data.len() < 5 {
        return Err("short control message".to_string());
    }
    let message_type = data[0];
    let payload_len = u32::from_be_bytes(data[1..5].try_into().unwrap()) as usize;
    if data.len() != payload_len + 5 {
        return Err("malformed control message length".to_string());
    }
    let payload = &data[5..];
    let mut msg = ControlMessage {
        message_type,
        ..ControlMessage::default()
    };
    match message_type {
        MESSAGE_SESSION_START => {
            if payload.len() != 79
                || u32::from_be_bytes(payload[0..4].try_into().unwrap()) != PERF_PROTOCOL_VERSION
            {
                return Err("malformed session_start".to_string());
            }
            let mode = match payload[4] {
                MODE_CODE_BULK => "bulk",
                MODE_CODE_RR => "rr",
                MODE_CODE_CRR => "crr",
                MODE_CODE_PERSISTENT_RR => "persistent-rr",
                _ => return Err("malformed session_start mode".to_string()),
            };
            let direction = match payload[5] {
                DIRECTION_CODE_UPLOAD => "upload",
                DIRECTION_CODE_DOWNLOAD => "download",
                _ => return Err("malformed session_start direction".to_string()),
            };
            let flags = payload[22];
            let start = SessionStart {
                mode: mode.to_string(),
                direction: direction.to_string(),
                request_bytes: u64::from_be_bytes(payload[6..14].try_into().unwrap()),
                response_bytes: u64::from_be_bytes(payload[14..22].try_into().unwrap()),
                total_bytes: OptionalU64 {
                    value: u64::from_be_bytes(payload[23..31].try_into().unwrap()),
                    set: flags & 0x01 != 0,
                },
                requests: OptionalU64 {
                    value: u64::from_be_bytes(payload[31..39].try_into().unwrap()),
                    set: flags & 0x02 != 0,
                },
                warmup: Duration::from_micros(u64::from_be_bytes(
                    payload[39..47].try_into().unwrap(),
                )),
                duration: Duration::from_micros(u64::from_be_bytes(
                    payload[47..55].try_into().unwrap(),
                )),
                streams: u64::from_be_bytes(payload[55..63].try_into().unwrap()),
                connections: u64::from_be_bytes(payload[63..71].try_into().unwrap()),
                requests_in_flight: u64::from_be_bytes(payload[71..79].try_into().unwrap()),
            };
            if start.streams == 0 || start.connections == 0 || start.requests_in_flight == 0 {
                return Err("malformed session_start counts".to_string());
            }
            if start.mode == "persistent-rr"
                && (start.request_bytes == 0 || start.response_bytes == 0)
            {
                return Err("persistent-rr requires nonzero request and response bytes".to_string());
            }
            msg.start = Some(start);
        }
        MESSAGE_SESSION_READY => {
            if payload.len() != 4 {
                return Err("malformed session_ready".to_string());
            }
            msg.ready = u32::from_be_bytes(payload.try_into().unwrap()) == PERF_PROTOCOL_VERSION;
        }
        MESSAGE_SESSION_ERROR => {
            if payload.len() < 4 {
                return Err("malformed session_error".to_string());
            }
            let len = u32::from_be_bytes(payload[0..4].try_into().unwrap()) as usize;
            if payload.len() != len + 4 {
                return Err("malformed session_error length".to_string());
            }
            msg.error_reason = String::from_utf8_lossy(&payload[4..]).into_owned();
        }
        MESSAGE_SESSION_COMPLETE => {}
        _ => return Err("unknown control message".to_string()),
    }
    Ok(msg)
}

fn listen_addr(cfg: &Config) -> Result<SocketAddr, AnyError> {
    let host = if cfg.host == "0.0.0.0" {
        "0.0.0.0".to_string()
    } else {
        cfg.host.clone()
    };
    let mut addrs = (host.as_str(), cfg.port).to_socket_addrs()?;
    addrs
        .next()
        .ok_or_else(|| format!("could not resolve listen address {}:{}", cfg.host, cfg.port).into())
}

async fn send_output(socket: &UdpSocket, dgram: Datagram) -> Result<(), AnyError> {
    socket.writable().await?;
    socket.send_to(&dgram, dgram.destination()).await?;
    Ok(())
}

async fn drain_client_output(
    conn: &mut Connection,
    socket: &UdpSocket,
) -> Result<Option<Duration>, AnyError> {
    loop {
        match conn.process(None::<Datagram>, Instant::now()) {
            Output::Datagram(dgram) => send_output(socket, dgram).await?,
            Output::Callback(timeout) => return Ok(Some(timeout)),
            Output::None => return Ok(None),
        }
    }
}

async fn drain_server_output(
    server: &mut PerfServer,
    socket: &UdpSocket,
) -> Result<Option<Duration>, AnyError> {
    loop {
        match server.process(None, Instant::now()) {
            Output::Datagram(dgram) => send_output(socket, dgram).await?,
            Output::Callback(timeout) => return Ok(Some(timeout)),
            Output::None => return Ok(None),
        }
    }
}

async fn handle_process_output(
    socket: &UdpSocket,
    output: Output,
) -> Result<Option<Duration>, AnyError> {
    match output {
        Output::Datagram(dgram) => {
            send_output(socket, dgram).await?;
            Ok(None)
        }
        Output::Callback(timeout) => Ok(Some(timeout)),
        Output::None => Ok(None),
    }
}

async fn drain_client_socket(
    socket: &UdpSocket,
    conn: &mut Connection,
    local_addr: SocketAddr,
) -> Result<Option<Duration>, AnyError> {
    let mut buf = [0u8; READ_BUF_SIZE];
    let mut next_timeout = None;
    loop {
        match socket.try_recv_from(&mut buf) {
            Ok((read, remote)) => {
                let dgram = Datagram::new(remote, local_addr, Tos::default(), buf[..read].to_vec());
                if let Some(timeout) =
                    handle_process_output(socket, conn.process(Some(dgram), Instant::now())).await?
                {
                    next_timeout = Some(timeout);
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => return Ok(next_timeout),
            Err(err) => return Err(err.into()),
        }
    }
}

async fn drain_server_socket(
    socket: &UdpSocket,
    server: &mut PerfServer,
    local_addr: SocketAddr,
) -> Result<Option<Duration>, AnyError> {
    let mut buf = [0u8; READ_BUF_SIZE];
    let mut next_timeout = None;
    loop {
        match socket.try_recv_from(&mut buf) {
            Ok((read, remote)) => {
                let dgram = Datagram::new(remote, local_addr, Tos::default(), buf[..read].to_vec());
                if let Some(timeout) =
                    handle_process_output(socket, server.process(Some(dgram), Instant::now()))
                        .await?
                {
                    next_timeout = Some(timeout);
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => return Ok(next_timeout),
            Err(err) => return Err(err.into()),
        }
    }
}

async fn wait_socket(socket: &UdpSocket, timeout: Option<Duration>) -> Result<(), AnyError> {
    let wait = timeout.unwrap_or(DEFAULT_WAIT);
    if wait.is_zero() {
        return Ok(());
    }
    match time::timeout(wait, socket.readable()).await {
        Ok(result) => result.map_err(AnyError::from),
        Err(_) => Ok(()),
    }
}

async fn wait_client_sockets(
    clients: &[NeqoClientBatch],
    timeout: Option<Duration>,
) -> Result<(), AnyError> {
    let wait = timeout.unwrap_or(DEFAULT_WAIT).min(DEFAULT_WAIT);
    if wait.is_zero() || clients.is_empty() {
        return Ok(());
    }

    let mut readable = FuturesUnordered::new();
    for client in clients {
        readable.push(client.socket.readable());
    }

    match time::timeout(wait, readable.next()).await {
        Ok(Some(result)) => result.map(|_| ()).map_err(AnyError::from),
        Ok(None) | Err(_) => Ok(()),
    }
}

fn earlier_timeout(current: Option<Duration>, next: Option<Duration>) -> Option<Duration> {
    match (current, next) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (Some(timeout), None) | (None, Some(timeout)) => Some(timeout),
        (None, None) => None,
    }
}

async fn run_request_batch(
    cfg: &Config,
    count: u64,
    shape: RequestShape,
    counters: &mut Counters,
) -> Result<(), String> {
    if count == 0 {
        return Ok(());
    }
    let count = count.min(DEFAULT_MAX_RUN_REQUESTS);
    let mut clients = open_client_batches(cfg, count, shape).await?;
    distribute_batch_requests(&mut clients, count);
    let started = Instant::now();
    while total_completed(&clients) < count && started.elapsed() < BATCH_TIMEOUT {
        drive_batches(&mut clients, counters).await?;
        if total_completed(&clients) >= count {
            break;
        }
    }
    if total_completed(&clients) >= count {
        close_batches(&mut clients).await;
        Ok(())
    } else {
        Err(format!(
            "neqo-perf completed {} of {} requests",
            total_completed(&clients),
            count
        ))
    }
}

async fn connect_client(cfg: &Config) -> Result<(UdpSocket, SocketAddr, Connection), String> {
    init().map_err(|err| format!("neqo NSS init failed: {err}"))?;

    let remote_addr =
        resolve_remote(&cfg.host, cfg.port).map_err(|err| format!("resolve failed: {err}"))?;
    let std_socket = StdUdpSocket::bind(bind_addr_for(remote_addr))
        .map_err(|err| format!("socket bind failed: {err}"))?;
    std_socket
        .connect(remote_addr)
        .map_err(|err| format!("socket connect failed: {err}"))?;
    std_socket
        .set_nonblocking(true)
        .map_err(|err| format!("socket nonblocking failed: {err}"))?;
    let local_addr = std_socket
        .local_addr()
        .map_err(|err| format!("socket local_addr failed: {err}"))?;
    let socket = UdpSocket::from_std(std_socket)
        .map_err(|err| format!("tokio socket setup failed: {err}"))?;

    let cid_mgr = Rc::new(RefCell::new(EmptyConnectionIdGenerator::default()));
    let conn = Connection::new_client(
        cfg.server_name.clone(),
        &[APPLICATION_PROTOCOL],
        cid_mgr,
        local_addr,
        remote_addr,
        connection_params(cfg),
        Instant::now(),
    )
    .map_err(|err| format!("neqo client connection failed: {err}"))?;

    Ok((socket, local_addr, conn))
}

struct NeqoClientBatch {
    socket: UdpSocket,
    local_addr: SocketAddr,
    conn: Connection,
    batch: ClientBatch,
}

async fn open_client_batches(
    cfg: &Config,
    target_requests: u64,
    shape: RequestShape,
) -> Result<Vec<NeqoClientBatch>, String> {
    let mut clients = Vec::new();
    let count = if (cfg.mode == "rr" || cfg.mode == "persistent-rr") && cfg.requests.set {
        rr_connection_target(cfg)
    } else {
        cfg.connections
    };
    for index in 0..count {
        let (socket, local_addr, conn) = connect_client(cfg).await?;
        let connection_target =
            if (cfg.mode == "rr" || cfg.mode == "persistent-rr") && cfg.requests.set {
                rr_request_limit_for_connection(cfg, index)
            } else {
                target_requests
            };
        clients.push(NeqoClientBatch {
            socket,
            local_addr,
            conn,
            batch: ClientBatch::new(cfg, connection_target, shape),
        });
    }
    let started = Instant::now();
    while clients.iter().any(|client| !client.batch.session_ready) {
        drive_batches(&mut clients, &mut Counters::default()).await?;
        if started.elapsed() > HANDSHAKE_TIMEOUT {
            return Err("neqo session_ready timed out".to_string());
        }
    }
    Ok(clients)
}

fn distribute_batch_requests(clients: &mut [NeqoClientBatch], count: u64) {
    if clients
        .iter()
        .map(|client| client.batch.target_requests)
        .sum::<u64>()
        == count
    {
        return;
    }
    for client in clients.iter_mut() {
        client.batch.target_requests = 0;
        client.batch.started_requests = 0;
    }
    for i in 0..count {
        let index = (i as usize) % clients.len();
        clients[index].batch.target_requests += 1;
    }
}

fn total_completed(clients: &[NeqoClientBatch]) -> u64 {
    clients
        .iter()
        .map(|client| client.batch.completed_requests)
        .sum()
}

fn total_active(clients: &[NeqoClientBatch]) -> u64 {
    clients
        .iter()
        .map(|client| client.batch.active_requests())
        .sum()
}

async fn drive_batches(
    clients: &mut [NeqoClientBatch],
    counters: &mut Counters,
) -> Result<(), String> {
    let mut next_timeout = None;
    for client in clients.iter_mut() {
        client.batch.handle_events(&mut client.conn, counters)?;
        let timeout = drain_client_output(&mut client.conn, &client.socket)
            .await
            .map_err(|err| format!("neqo output failed: {err}"))?;
        next_timeout = earlier_timeout(next_timeout, timeout);
    }
    for client in clients.iter_mut() {
        let timeout = drain_client_socket(&client.socket, &mut client.conn, client.local_addr)
            .await
            .map_err(|err| format!("neqo socket read failed: {err}"))?;
        next_timeout = earlier_timeout(next_timeout, timeout);
    }
    if total_active(clients) > 0 || clients.iter().any(|client| !client.batch.session_ready) {
        wait_client_sockets(clients, next_timeout)
            .await
            .map_err(|err| format!("neqo socket wait failed: {err}"))?;
    }
    Ok(())
}

async fn close_batches(clients: &mut [NeqoClientBatch]) {
    for client in clients {
        let _ = client.batch.close_persistent_streams(&mut client.conn);
        let _ = drain_client_output(&mut client.conn, &client.socket).await;
        client.conn.close(Instant::now(), 0, "done");
        let _ = drain_client_output(&mut client.conn, &client.socket).await;
    }
}

fn rr_connection_target(cfg: &Config) -> u64 {
    if (cfg.mode == "rr" || cfg.mode == "persistent-rr") && cfg.requests.set {
        cfg.connections.min(cfg.requests.value)
    } else {
        cfg.connections
    }
}

fn rr_request_limit_for_connection(cfg: &Config, connection_index: u64) -> u64 {
    let connections = rr_connection_target(cfg);
    if connections == 0 {
        return 0;
    }
    let base = cfg.requests.value / connections;
    let remainder = cfg.requests.value % connections;
    base + u64::from(connection_index < remainder)
}

async fn run_timed_bulk(
    cfg: &Config,
    shape: RequestShape,
    counters: &mut Counters,
) -> Result<(), String> {
    let mut clients = open_client_batches(cfg, u64::MAX, shape).await?;
    for client in &mut clients {
        client.batch.max_active_requests = Some(cfg.streams.max(1));
    }

    let started = Instant::now();
    let deadline = started + cfg.duration;
    let drain_deadline = deadline + DRAIN_TIMEOUT;
    while Instant::now() < drain_deadline {
        if Instant::now() >= deadline {
            for client in &mut clients {
                client.batch.target_requests = client.batch.started_requests;
            }
        }
        drive_batches(&mut clients, counters).await?;
        if Instant::now() >= deadline && total_active(&clients) == 0 {
            break;
        }
    }

    close_batches(&mut clients).await;
    Ok(())
}

async fn run_bulk(cfg: &Config, counters: &mut Counters) -> Result<(), String> {
    let (request_bytes, response_bytes, unit) = if cfg.direction == "upload" {
        let request_bytes = cfg.request_bytes.max(cfg.response_bytes);
        (request_bytes, 0, request_bytes.max(1))
    } else {
        (
            cfg.request_bytes,
            cfg.response_bytes,
            cfg.response_bytes.max(1),
        )
    };
    let shape = RequestShape {
        request_bytes,
        response_bytes,
        counts_latency: false,
    };

    if cfg.total_bytes.set {
        let mut count = ceil_div(cfg.total_bytes.value, unit);
        if count == 0 {
            count = 1;
        }
        return run_request_batch(cfg, count, shape, counters).await;
    }

    run_timed_bulk(cfg, shape, counters).await
}

async fn run_rr(cfg: &Config, counters: &mut Counters) -> Result<(), String> {
    let shape = RequestShape {
        request_bytes: cfg.request_bytes,
        response_bytes: cfg.response_bytes,
        counts_latency: true,
    };
    if cfg.requests.set {
        return run_request_batch(cfg, cfg.requests.value, shape, counters).await;
    }

    let mut clients = open_client_batches(cfg, u64::MAX, shape).await?;
    for client in &mut clients {
        client.batch.max_active_requests = Some(cfg.requests_in_flight.max(1));
    }

    let started = Instant::now();
    let deadline = started + cfg.duration;
    let drain_deadline = deadline + DRAIN_TIMEOUT;
    while Instant::now() < drain_deadline {
        if Instant::now() >= deadline {
            for client in &mut clients {
                client.batch.target_requests = client.batch.started_requests;
            }
        }
        drive_batches(&mut clients, counters).await?;
        if Instant::now() >= deadline && total_active(&clients) == 0 {
            break;
        }
    }

    close_batches(&mut clients).await;
    Ok(())
}

fn merge_counters(dst: &mut Counters, mut src: Counters) {
    dst.bytes_sent += src.bytes_sent;
    dst.bytes_received += src.bytes_received;
    dst.requests_completed += src.requests_completed;
    dst.skipped_setup_errors += src.skipped_setup_errors;
    dst.latencies.append(&mut src.latencies);
}

async fn run_single_crr_request(cfg: &Config, shape: RequestShape) -> Result<Counters, String> {
    let mut counters = Counters::default();
    let (socket, local_addr, conn) = connect_client(cfg)
        .await
        .map_err(|err| format!("neqo CRR connect failed: {err}"))?;
    let mut client = NeqoClientBatch {
        socket,
        local_addr,
        conn,
        batch: ClientBatch::new(cfg, 1, shape),
    };
    let started = Instant::now();
    while client.batch.completed_requests < 1 && started.elapsed() < BATCH_TIMEOUT {
        drive_batches(std::slice::from_mut(&mut client), &mut counters).await?;
        if client.batch.completed_requests >= 1 {
            break;
        }
    }
    close_batches(std::slice::from_mut(&mut client)).await;
    if client.batch.completed_requests < 1 {
        return Err(format!(
            "neqo-perf completed {} of 1 CRR requests",
            client.batch.completed_requests
        ));
    }
    Ok(counters)
}

async fn run_crr(cfg: &Config, counters: &mut Counters) -> Result<(), String> {
    let shape = RequestShape {
        request_bytes: cfg.request_bytes,
        response_bytes: cfg.response_bytes,
        counts_latency: true,
    };

    let mut active = FuturesUnordered::new();
    let mut started = 0_u64;
    let deadline = Instant::now() + cfg.duration;

    loop {
        while (active.len() as u64) < cfg.connections {
            if cfg.requests.set {
                if started >= cfg.requests.value {
                    break;
                }
            } else if Instant::now() >= deadline {
                break;
            }

            active.push(run_single_crr_request(cfg, shape));
            started += 1;
        }

        if active.is_empty() {
            break;
        }

        let Some(result) = active.next().await else {
            break;
        };
        merge_counters(counters, result?);
    }

    Ok(())
}

async fn run_client(cfg: &Config) -> RunSummary<'_> {
    let mut counters = Counters::default();
    let start = Instant::now();
    if !cfg.warmup.is_zero() && !cfg.requests.set && !cfg.total_bytes.set {
        time::sleep(cfg.warmup).await;
    }
    let measure_start = Instant::now();
    let rc = if cfg.mode == "bulk" {
        run_bulk(cfg, &mut counters).await
    } else if cfg.mode == "rr" || cfg.mode == "persistent-rr" {
        run_rr(cfg, &mut counters).await
    } else {
        run_crr(cfg, &mut counters).await
    };
    let elapsed = if !cfg.requests.set && !cfg.total_bytes.set && rc.is_ok() {
        cfg.duration
    } else if cfg.requests.set {
        start.elapsed()
    } else {
        measure_start.elapsed()
    };
    make_summary(
        cfg,
        counters,
        elapsed,
        if rc.is_ok() { "ok" } else { "failed" },
        rc.err(),
    )
}

async fn run_server(cfg: &Config) -> Result<(), AnyError> {
    let listen = listen_addr(cfg)?;
    let std_socket = StdUdpSocket::bind(listen)?;
    std_socket.set_nonblocking(true)?;
    let local_addr = std_socket.local_addr()?;
    let socket = UdpSocket::from_std(std_socket)?;
    let mut server = PerfServer::new(cfg)?;

    loop {
        let socket_timeout = drain_server_socket(&socket, &mut server, local_addr).await?;
        server
            .process_events()
            .map_err(|err| format!("neqo server event failed: {err}"))?;
        let next_timeout = drain_server_output(&mut server, &socket).await?;
        wait_socket(
            &socket,
            next_timeout.or(socket_timeout).or(Some(SERVER_POLL)),
        )
        .await?;
    }
}

fn make_summary<'a>(
    cfg: &'a Config,
    counters: Counters,
    elapsed: Duration,
    status: &'a str,
    failure_reason: Option<String>,
) -> RunSummary<'a> {
    let elapsed_ms = duration_millis(elapsed);
    let seconds = (elapsed_ms as f64 / 1000.0).max(0.001);
    let total_bytes = counters.bytes_sent + counters.bytes_received;
    RunSummary {
        status,
        failure_reason,
        cfg,
        elapsed_ms,
        latency: summarize_latency(&counters.latencies),
        throughput_mib_per_s: total_bytes as f64 / (1024.0 * 1024.0) / seconds,
        throughput_gbit_per_s: (total_bytes as f64 * 8.0) / 1_000_000_000.0 / seconds,
        requests_per_s: counters.requests_completed as f64 / seconds,
        counters,
    }
}

fn summarize_latency(samples: &[Duration]) -> LatencySummary {
    if samples.is_empty() {
        return LatencySummary::default();
    }
    let mut micros: Vec<u64> = samples
        .iter()
        .map(|sample| duration_micros(*sample))
        .collect();
    micros.sort_unstable();
    let sum: u64 = micros.iter().sum();
    LatencySummary {
        min_us: micros[0],
        avg_us: sum / micros.len() as u64,
        p50_us: percentile(&micros, 50),
        p90_us: percentile(&micros, 90),
        p99_us: percentile(&micros, 99),
        max_us: micros[micros.len() - 1],
    }
}

fn percentile(values: &[u64], pct: usize) -> u64 {
    if values.is_empty() {
        return 0;
    }
    let mut rank = (values.len() * pct).div_ceil(100);
    if rank == 0 {
        rank = 1;
    }
    values[rank.min(values.len()) - 1]
}

fn duration_millis(duration: Duration) -> u64 {
    duration.as_millis().try_into().unwrap_or(u64::MAX)
}

fn duration_micros(duration: Duration) -> u64 {
    duration.as_micros().try_into().unwrap_or(u64::MAX)
}

fn ceil_div(n: u64, d: u64) -> u64 {
    if d == 0 {
        0
    } else {
        (n + d - 1) / d
    }
}

fn encode_be64(out: &mut [u8], value: u64) {
    out.copy_from_slice(&value.to_be_bytes());
}

fn decode_be64(input: &[u8]) -> u64 {
    let mut bytes = [0; 8];
    bytes.copy_from_slice(input);
    u64::from_be_bytes(bytes)
}

fn json_string(value: &str) -> String {
    let mut out = String::from("\"");
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn write_summary_json(out: &mut dyn Write, summary: &RunSummary<'_>) -> std::io::Result<()> {
    let cfg = summary.cfg;
    writeln!(out, "{{")?;
    writeln!(out, "  \"schema_version\": 1,")?;
    writeln!(out, "  \"status\": {},", json_string(summary.status))?;
    if let Some(reason) = &summary.failure_reason {
        writeln!(out, "  \"failure_reason\": {},", json_string(reason))?;
    }
    writeln!(out, "  \"mode\": {},", json_string(&cfg.mode))?;
    writeln!(out, "  \"direction\": {},", json_string(&cfg.direction))?;
    writeln!(out, "  \"backend\": {},", json_string(&cfg.io_backend))?;
    writeln!(
        out,
        "  \"congestion_control\": {},",
        json_string(&cfg.congestion_control)
    )?;
    writeln!(out, "  \"remote_host\": {},", json_string(&cfg.host))?;
    writeln!(out, "  \"remote_port\": {},", cfg.port)?;
    writeln!(out, "  \"alpn\": {},", json_string(APPLICATION_PROTOCOL))?;
    writeln!(out, "  \"elapsed_ms\": {},", summary.elapsed_ms)?;
    writeln!(out, "  \"warmup_ms\": {},", duration_millis(cfg.warmup))?;
    writeln!(out, "  \"bytes_sent\": {},", summary.counters.bytes_sent)?;
    writeln!(
        out,
        "  \"bytes_received\": {},",
        summary.counters.bytes_received
    )?;
    writeln!(out, "  \"server_counters\": {{")?;
    writeln!(
        out,
        "    \"bytes_sent\": {},",
        summary.counters.bytes_received
    )?;
    writeln!(
        out,
        "    \"bytes_received\": {},",
        summary.counters.bytes_sent
    )?;
    writeln!(
        out,
        "    \"requests_completed\": {}",
        summary.counters.requests_completed
    )?;
    writeln!(out, "  }},")?;
    writeln!(
        out,
        "  \"requests_completed\": {},",
        summary.counters.requests_completed
    )?;
    if summary.counters.skipped_setup_errors > 0 {
        writeln!(
            out,
            "  \"skipped_setup_errors\": {},",
            summary.counters.skipped_setup_errors
        )?;
    }
    writeln!(out, "  \"streams\": {},", cfg.streams)?;
    writeln!(out, "  \"connections\": {},", cfg.connections)?;
    writeln!(out, "  \"requests_in_flight\": {},", cfg.requests_in_flight)?;
    writeln!(out, "  \"request_bytes\": {},", cfg.request_bytes)?;
    writeln!(out, "  \"response_bytes\": {},", cfg.response_bytes)?;
    writeln!(
        out,
        "  \"throughput_mib_per_s\": {:.6},",
        summary.throughput_mib_per_s
    )?;
    writeln!(
        out,
        "  \"throughput_gbit_per_s\": {:.6},",
        summary.throughput_gbit_per_s
    )?;
    writeln!(out, "  \"requests_per_s\": {:.6},", summary.requests_per_s)?;
    writeln!(out, "  \"latency\": {{")?;
    writeln!(out, "    \"min_us\": {},", summary.latency.min_us)?;
    writeln!(out, "    \"avg_us\": {},", summary.latency.avg_us)?;
    writeln!(out, "    \"p50_us\": {},", summary.latency.p50_us)?;
    writeln!(out, "    \"p90_us\": {},", summary.latency.p90_us)?;
    writeln!(out, "    \"p99_us\": {},", summary.latency.p99_us)?;
    writeln!(out, "    \"max_us\": {}", summary.latency.max_us)?;
    writeln!(out, "  }}")?;
    writeln!(out, "}}")?;
    Ok(())
}

fn emit_summary(summary: &RunSummary<'_>) -> Result<(), AnyError> {
    println!(
        "status={} mode={} cc={} direction={} throughput_mib/s={:.3} throughput_gbit/s={:.3} requests/s={:.3}",
        summary.status,
        summary.cfg.mode,
        summary.cfg.congestion_control,
        summary.cfg.direction,
        summary.throughput_mib_per_s,
        summary.throughput_gbit_per_s,
        summary.requests_per_s
    );
    if let Some(path) = &summary.cfg.json_out {
        let mut file = File::create(path)?;
        write_summary_json(&mut file, summary)?;
    }
    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let cfg = match parse_args() {
        Ok(cfg) => cfg,
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(2);
        }
    };

    if cfg.role == "server" {
        if let Err(err) = run_server(&cfg).await {
            eprintln!("{err}");
            std::process::exit(1);
        }
        return;
    }

    let summary = run_client(&cfg).await;
    if let Err(err) = emit_summary(&summary) {
        eprintln!("{err}");
        std::process::exit(1);
    }
    if summary.status != "ok" {
        std::process::exit(1);
    }
}

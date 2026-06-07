use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{ClientConfig, Connection, Endpoint, RecvStream, SendStream, ServerConfig};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use serde::Serialize;
use std::cmp;
use std::env;
use std::fs;
use std::io;
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, Mutex};
use tokio::time;

const PROTOCOL_VERSION: u32 = 3;
const APPLICATION_PROTOCOL: &[u8] = b"coquic-perf/1";
const TRANSFER_CONNECTION_WINDOW: u64 = 32 * 1024 * 1024;
const TRANSFER_STREAM_WINDOW: u64 = 16 * 1024 * 1024;
const SERVER_READY_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_DRAIN_TIMEOUT: Duration = Duration::from_secs(2);
const WRITE_CHUNK_SIZE: usize = 32 * 1024;
const READ_CHUNK_SIZE: usize = 64 * 1024;

const MESSAGE_SESSION_START: u8 = 1;
const MESSAGE_SESSION_READY: u8 = 2;
const MESSAGE_SESSION_ERROR: u8 = 3;
const MESSAGE_SESSION_COMPLETE: u8 = 4;

const MODE_BULK: &str = "bulk";
const MODE_RR: &str = "rr";
const MODE_CRR: &str = "crr";
const DIRECTION_UPLOAD: &str = "upload";
const DIRECTION_DOWNLOAD: &str = "download";

type AnyError = Box<dyn std::error::Error + Send + Sync + 'static>;

#[derive(Clone)]
struct Config {
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
}

#[derive(Clone, Copy, Default)]
struct OptionalU64 {
    value: u64,
    set: bool,
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

#[derive(Default, Clone, Copy)]
struct SessionComplete {
    bytes_sent: u64,
    bytes_received: u64,
    requests_completed: u64,
}

struct ControlMessage {
    message_type: u8,
    ready: bool,
    error_reason: String,
    start: Option<SessionStart>,
    complete: SessionComplete,
}

#[derive(Default)]
struct MeasuredCounters {
    bytes_sent: AtomicU64,
    bytes_received: AtomicU64,
    requests_completed: AtomicU64,
    skipped_setup_errors: AtomicU64,
    latencies: Mutex<Vec<Duration>>,
}

struct ConnectionState {
    _endpoint: Endpoint,
    conn: Connection,
    control_recv: Arc<Mutex<RecvStream>>,
}

#[derive(Default)]
struct BulkStreamResult {
    counts: bool,
    received: u64,
    err: Option<String>,
}

#[derive(Default)]
struct RRStreamResult {
    counts: bool,
    latency: Duration,
    received: u64,
    err: Option<String>,
}

struct ServerSession {
    control_send: Mutex<SendStream>,
    start: SessionStart,
    bytes_sent: AtomicU64,
    bytes_received: AtomicU64,
    requests_completed: AtomicU64,
    completed: AtomicU64,
}

#[derive(Serialize)]
struct RunSummary {
    schema_version: u32,
    status: String,
    mode: String,
    direction: String,
    backend: String,
    congestion_control: String,
    remote_host: String,
    remote_port: u16,
    alpn: String,
    elapsed_ms: i64,
    warmup_ms: i64,
    bytes_sent: u64,
    bytes_received: u64,
    server_counters: ServerCounters,
    requests_completed: u64,
    streams: u64,
    connections: u64,
    requests_in_flight: u64,
    request_bytes: u64,
    response_bytes: u64,
    throughput_mib_per_s: f64,
    throughput_gbit_per_s: f64,
    requests_per_s: f64,
    latency: LatencySummary,
    #[serde(skip_serializing_if = "String::is_empty")]
    failure_reason: String,
    #[serde(skip_serializing_if = "is_zero")]
    skipped_setup_errors: u64,
}

#[derive(Default, Serialize)]
struct ServerCounters {
    bytes_sent: u64,
    bytes_received: u64,
    requests_completed: u64,
}

#[derive(Default, Serialize)]
struct LatencySummary {
    min_us: u64,
    avg_us: u64,
    p50_us: u64,
    p90_us: u64,
    p99_us: u64,
    max_us: u64,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let mut args: Vec<String> = env::args().collect();
    if args.len() < 2 || (args[1] != "client" && args[1] != "server") {
        eprintln!("usage: quinn-perf [client|server] [options]");
        std::process::exit(2);
    }
    let role = args.remove(1);
    let cfg = match parse_args(&args[1..]) {
        Ok(cfg) => cfg,
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(2);
        }
    };

    if role == "server" {
        if let Err(err) = run_server(cfg).await {
            eprintln!("{err}");
            std::process::exit(1);
        }
        return;
    }

    let mut summary = new_run_summary(&cfg);
    let err = match run_client(&cfg).await {
        Ok(done) => {
            summary = done;
            None
        }
        Err(err) => Some(err),
    };
    if let Some(err) = err {
        summary.status = "failed".to_string();
        summary.failure_reason = err.to_string();
    }
    finalize_summary(&mut summary);
    if let Err(err) = emit_summary(&summary, cfg.json_out.as_deref()) {
        eprintln!("{err}");
        std::process::exit(1);
    }
    if summary.status != "ok" {
        std::process::exit(1);
    }
}

fn parse_args(args: &[String]) -> Result<Config, AnyError> {
    let mut cfg = Config {
        host: "127.0.0.1".to_string(),
        port: 4433,
        server_name: "localhost".to_string(),
        verify_peer: false,
        io_backend: "socket".to_string(),
        congestion_control: "newreno".to_string(),
        certificate_chain: "tests/fixtures/quic-server-cert.pem".to_string(),
        private_key: "tests/fixtures/quic-server-key.pem".to_string(),
        disable_pmtud: true,
        mode: MODE_BULK.to_string(),
        direction: DIRECTION_DOWNLOAD.to_string(),
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
    };

    let mut index = 0;
    while index < args.len() {
        let arg = args[index].as_str();
        index += 1;
        let take_value = |index: &mut usize| -> Result<String, AnyError> {
            if *index >= args.len() {
                return Err(format!("missing value for {arg}").into());
            }
            let value = args[*index].clone();
            *index += 1;
            Ok(value)
        };
        match arg {
            "--verify-peer" => cfg.verify_peer = true,
            "--disable-pmtud" => cfg.disable_pmtud = true,
            "--host" => cfg.host = take_value(&mut index)?,
            "--port" => cfg.port = take_value(&mut index)?.parse()?,
            "--server-name" => cfg.server_name = take_value(&mut index)?,
            "--io-backend" => cfg.io_backend = take_value(&mut index)?,
            "--congestion-control" => cfg.congestion_control = take_value(&mut index)?,
            "--certificate-chain" => cfg.certificate_chain = take_value(&mut index)?,
            "--private-key" => cfg.private_key = take_value(&mut index)?,
            "--mode" => cfg.mode = take_value(&mut index)?,
            "--direction" => cfg.direction = take_value(&mut index)?,
            "--request-bytes" => cfg.request_bytes = take_value(&mut index)?.parse()?,
            "--response-bytes" => cfg.response_bytes = take_value(&mut index)?.parse()?,
            "--streams" => cfg.streams = take_value(&mut index)?.parse()?,
            "--connections" => cfg.connections = take_value(&mut index)?.parse()?,
            "--requests-in-flight" => cfg.requests_in_flight = take_value(&mut index)?.parse()?,
            "--requests" => {
                cfg.requests = OptionalU64 {
                    value: take_value(&mut index)?.parse()?,
                    set: true,
                };
            }
            "--total-bytes" => {
                cfg.total_bytes = OptionalU64 {
                    value: take_value(&mut index)?.parse()?,
                    set: true,
                };
            }
            "--warmup" => cfg.warmup = parse_duration(&take_value(&mut index)?)?,
            "--duration" => cfg.duration = parse_duration(&take_value(&mut index)?)?,
            "--json-out" => cfg.json_out = Some(take_value(&mut index)?),
            _ => return Err(format!("unknown argument: {arg}").into()),
        }
    }

    if ![MODE_BULK, MODE_RR, MODE_CRR].contains(&cfg.mode.as_str()) {
        return Err(format!("unsupported mode: {}", cfg.mode).into());
    }
    if cfg.io_backend != "socket" && cfg.io_backend != "io_uring" {
        return Err(format!("unsupported io-backend label: {}", cfg.io_backend).into());
    }
    if !["newreno", "cubic", "bbr", "copa", "default"].contains(&cfg.congestion_control.as_str()) {
        return Err(format!(
            "unsupported congestion-control label: {}",
            cfg.congestion_control
        )
        .into());
    }
    if cfg.direction != DIRECTION_UPLOAD && cfg.direction != DIRECTION_DOWNLOAD {
        return Err(format!("unsupported direction: {}", cfg.direction).into());
    }
    if cfg.streams == 0 || cfg.connections == 0 || cfg.requests_in_flight == 0 {
        return Err(
            "streams, connections, and requests-in-flight must be greater than zero".into(),
        );
    }
    Ok(cfg)
}

fn parse_duration(value: &str) -> Result<Duration, AnyError> {
    if let Some(ms) = value.strip_suffix("ms") {
        return Ok(Duration::from_millis(ms.parse()?));
    }
    if let Some(s) = value.strip_suffix('s') {
        return Ok(Duration::from_secs(s.parse()?));
    }
    Err(format!("invalid duration: {value}").into())
}

async fn run_server(cfg: Config) -> Result<(), AnyError> {
    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            load_certs(&cfg.certificate_chain)?,
            load_private_key(&cfg.private_key)?,
        )?;
    server_crypto.alpn_protocols = vec![APPLICATION_PROTOCOL.to_vec()];
    let mut server_config =
        ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_crypto)?));
    configure_transport(&mut server_config.transport)?;
    let addr: SocketAddr = format!("{}:{}", cfg.host, cfg.port).parse()?;
    let endpoint = Endpoint::server(server_config, addr)?;

    while let Some(incoming) = endpoint.accept().await {
        tokio::spawn(async move {
            if let Err(err) = handle_server_connection(incoming).await {
                eprintln!("quinn server connection failed: {err}");
            }
        });
    }
    Ok(())
}

async fn handle_server_connection(incoming: quinn::Incoming) -> Result<(), AnyError> {
    let conn = incoming.await?;
    let (control_send, mut control_recv) = conn.accept_bi().await?;
    let msg = read_control_message(&mut control_recv).await?;
    let Some(start) = msg.start else {
        let _ = send_control_message(control_send, encode_session_error("expected session_start"))
            .await;
        conn.close(1u32.into(), b"invalid session_start");
        return Ok(());
    };

    let session = Arc::new(ServerSession {
        control_send: Mutex::new(control_send),
        start,
        bytes_sent: AtomicU64::new(0),
        bytes_received: AtomicU64::new(0),
        requests_completed: AtomicU64::new(0),
        completed: AtomicU64::new(0),
    });
    {
        let mut send = session.control_send.lock().await;
        send.write_all(&encode_session_ready()).await?;
    }
    loop {
        let stream = conn.accept_bi().await;
        let stream = match stream {
            Ok(stream) => stream,
            Err(_) => return Ok(()),
        };
        let session = session.clone();
        tokio::spawn(async move {
            let _ = handle_server_data_stream(session, stream).await;
        });
    }
}

async fn handle_server_data_stream(
    session: Arc<ServerSession>,
    (mut send, mut recv): (SendStream, RecvStream),
) -> Result<(), AnyError> {
    let received = copy_and_count(&mut recv).await?;
    session
        .bytes_received
        .fetch_add(received, Ordering::Relaxed);
    let requests_completed = session.requests_completed.fetch_add(1, Ordering::Relaxed) + 1;

    let mut response_bytes = 0;
    if session.start.mode == MODE_BULK
        && session.start.direction == DIRECTION_DOWNLOAD
        && session.start.total_bytes.set
    {
        let stream_index = requests_completed - 1;
        let per_stream = session.start.total_bytes.value / session.start.streams;
        let remainder = session.start.total_bytes.value % session.start.streams;
        response_bytes = per_stream + u64::from(stream_index < remainder);
    } else if session.start.mode == MODE_BULK && session.start.direction == DIRECTION_DOWNLOAD {
        response_bytes = session.start.response_bytes;
    } else if session.start.mode == MODE_RR || session.start.mode == MODE_CRR {
        response_bytes = session.start.response_bytes;
    }

    if response_bytes != 0 {
        let sent = write_n(&mut send, response_bytes).await?;
        session.bytes_sent.fetch_add(sent, Ordering::Relaxed);
    }
    send.finish()?;

    if should_send_session_complete(&session, requests_completed)
        && session
            .completed
            .compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
    {
        let complete = SessionComplete {
            bytes_sent: session.bytes_sent.load(Ordering::Relaxed),
            bytes_received: session.bytes_received.load(Ordering::Relaxed),
            requests_completed: session.requests_completed.load(Ordering::Relaxed),
        };
        let mut control = session.control_send.lock().await;
        control
            .write_all(&encode_session_complete(complete))
            .await?;
        control.finish()?;
    }
    Ok(())
}

fn should_send_session_complete(session: &ServerSession, requests_completed: u64) -> bool {
    if session.start.mode == MODE_BULK
        && session.start.total_bytes.set
        && requests_completed >= session.start.streams
    {
        return true;
    }
    if session.start.mode == MODE_BULK
        && session.start.direction == DIRECTION_UPLOAD
        && requests_completed >= session.start.streams
    {
        return true;
    }
    session.start.mode == MODE_RR
        && session.start.requests.set
        && requests_completed >= session.start.requests.value
}

async fn run_client(cfg: &Config) -> Result<RunSummary, AnyError> {
    let mut summary = new_run_summary(cfg);
    let start = SessionStart {
        mode: cfg.mode.clone(),
        direction: cfg.direction.clone(),
        request_bytes: cfg.request_bytes,
        response_bytes: cfg.response_bytes,
        total_bytes: cfg.total_bytes,
        requests: cfg.requests,
        warmup: cfg.warmup,
        duration: cfg.duration,
        streams: cfg.streams,
        connections: cfg.connections,
        requests_in_flight: cfg.requests_in_flight,
    };

    let mut connections = Vec::new();
    if cfg.mode != MODE_CRR {
        connections = open_connections(cfg, &start, cfg.connections).await?;
    }

    let counters = Arc::new(MeasuredCounters::default());
    let run_start = Instant::now();
    let elapsed = match cfg.mode.as_str() {
        MODE_BULK => {
            if cfg.direction == DIRECTION_DOWNLOAD && !cfg.total_bytes.set {
                run_timed_bulk_download(cfg, &connections, counters.clone()).await?;
                cfg.duration
            } else {
                run_fixed_bulk(cfg, &connections, counters.clone()).await?;
                run_start.elapsed()
            }
        }
        MODE_RR => {
            run_rr(cfg, &connections, counters.clone()).await?;
            if cfg.requests.set {
                run_start.elapsed()
            } else {
                cfg.duration
            }
        }
        MODE_CRR => {
            run_crr(cfg, &start, counters.clone()).await?;
            if cfg.requests.set {
                run_start.elapsed()
            } else {
                cfg.duration
            }
        }
        _ => unreachable!(),
    };
    summary.elapsed_ms = duration_millis(elapsed);

    let mut complete = SessionComplete::default();
    if expects_session_complete(cfg) {
        complete = read_first_complete(&connections).await.unwrap_or_default();
    }
    summary.server_counters = ServerCounters {
        bytes_sent: complete.bytes_sent,
        bytes_received: complete.bytes_received,
        requests_completed: complete.requests_completed,
    };
    summary.bytes_sent = counters.bytes_sent.load(Ordering::Relaxed);
    summary.bytes_received = counters.bytes_received.load(Ordering::Relaxed);
    summary.requests_completed = counters.requests_completed.load(Ordering::Relaxed);
    summary.skipped_setup_errors = counters.skipped_setup_errors.load(Ordering::Relaxed);
    if cfg.mode == MODE_RR || cfg.mode == MODE_CRR || !expects_session_complete(cfg) {
        summary.server_counters.bytes_sent = summary.bytes_received;
        summary.server_counters.bytes_received = summary.bytes_sent;
        summary.server_counters.requests_completed = summary.requests_completed;
    }
    let latencies = counters.latencies.lock().await;
    summary.latency = summarize_latency(&latencies);
    Ok(summary)
}

fn new_run_summary(cfg: &Config) -> RunSummary {
    RunSummary {
        schema_version: 1,
        status: "ok".to_string(),
        mode: cfg.mode.clone(),
        direction: cfg.direction.clone(),
        backend: "quinn".to_string(),
        congestion_control: cfg.congestion_control.clone(),
        remote_host: cfg.host.clone(),
        remote_port: cfg.port,
        alpn: String::from_utf8_lossy(APPLICATION_PROTOCOL).into_owned(),
        elapsed_ms: 0,
        warmup_ms: duration_millis(cfg.warmup),
        bytes_sent: 0,
        bytes_received: 0,
        server_counters: ServerCounters::default(),
        requests_completed: 0,
        streams: cfg.streams,
        connections: cfg.connections,
        requests_in_flight: cfg.requests_in_flight,
        request_bytes: cfg.request_bytes,
        response_bytes: cfg.response_bytes,
        throughput_mib_per_s: 0.0,
        throughput_gbit_per_s: 0.0,
        requests_per_s: 0.0,
        latency: LatencySummary::default(),
        failure_reason: String::new(),
        skipped_setup_errors: 0,
    }
}

fn expects_session_complete(cfg: &Config) -> bool {
    (cfg.mode == MODE_BULK && cfg.total_bytes.set) || (cfg.mode == MODE_RR && cfg.requests.set)
}

async fn open_connections(
    cfg: &Config,
    start: &SessionStart,
    count: u64,
) -> Result<Vec<ConnectionState>, AnyError> {
    let mut out = Vec::with_capacity(int_cap(count));
    for _ in 0..count {
        let endpoint = client_endpoint(cfg)?;
        let remote = resolve_remote(&cfg.host, cfg.port)?;
        let conn = endpoint.connect(remote, &cfg.server_name)?.await?;
        let (mut control_send, mut control_recv) = conn.open_bi().await?;
        control_send.write_all(&encode_session_start(start)).await?;
        control_send.finish()?;
        wait_for_ready(&mut control_recv).await?;
        out.push(ConnectionState {
            _endpoint: endpoint,
            conn,
            control_recv: Arc::new(Mutex::new(control_recv)),
        });
    }
    Ok(out)
}

fn client_endpoint(cfg: &Config) -> Result<Endpoint, AnyError> {
    let mut endpoint = Endpoint::client("[::]:0".parse()?)?;
    endpoint.set_default_client_config(client_config(cfg)?);
    Ok(endpoint)
}

fn client_config(cfg: &Config) -> Result<ClientConfig, AnyError> {
    let mut client_crypto = if cfg.verify_peer {
        let mut roots = rustls::RootCertStore::empty();
        for cert in load_certs(&cfg.certificate_chain)? {
            roots.add(cert)?;
        }
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth()
    } else {
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(SkipServerVerification::new())
            .with_no_client_auth()
    };
    client_crypto.alpn_protocols = vec![APPLICATION_PROTOCOL.to_vec()];
    let mut cfg = ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_crypto)?));
    cfg.transport_config(make_transport_config()?);
    Ok(cfg)
}

fn configure_transport(transport: &mut Arc<quinn::TransportConfig>) -> Result<(), AnyError> {
    *transport = make_transport_config()?;
    Ok(())
}

fn make_transport_config() -> Result<Arc<quinn::TransportConfig>, AnyError> {
    let mut transport = quinn::TransportConfig::default();
    transport.receive_window(TRANSFER_CONNECTION_WINDOW.try_into()?);
    transport.stream_receive_window(TRANSFER_STREAM_WINDOW.try_into()?);
    transport.max_concurrent_bidi_streams(4096_u32.into());
    transport.max_concurrent_uni_streams(0_u8.into());
    Ok(Arc::new(transport))
}

fn resolve_remote(host: &str, port: u16) -> Result<SocketAddr, AnyError> {
    (host, port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| format!("unable to resolve {host}:{port}").into())
}

async fn wait_for_ready(control: &mut RecvStream) -> Result<(), AnyError> {
    let msg = time::timeout(SERVER_READY_TIMEOUT, read_control_message(control)).await??;
    if msg.message_type == MESSAGE_SESSION_ERROR {
        return Err(format!("server session error: {}", msg.error_reason).into());
    }
    if msg.message_type != MESSAGE_SESSION_READY || !msg.ready {
        return Err(format!(
            "unexpected control message type {} while waiting for ready",
            msg.message_type
        )
        .into());
    }
    Ok(())
}

async fn run_timed_bulk_download(
    cfg: &Config,
    connections: &[ConnectionState],
    counters: Arc<MeasuredCounters>,
) -> Result<(), AnyError> {
    let measure_start = Instant::now() + cfg.warmup;
    let measure_deadline = measure_start + cfg.duration;
    let (tx, mut rx) = mpsc::channel(int_cap(cfg.streams * cfg.connections + 64));
    let active = Arc::new(AtomicU64::new(0));
    let next_connection = AtomicU64::new(0);

    for c in connections {
        for _ in 0..cfg.streams {
            open_bulk_download(c.conn.clone(), false, tx.clone(), active.clone());
        }
    }

    time::sleep_until(tokio::time::Instant::from_std(measure_start)).await;
    while Instant::now() < measure_deadline {
        let result = rx.recv().await.ok_or("bulk result channel closed")?;
        if let Some(err) = result.err {
            return Err(err.into());
        }
        if result.counts {
            counters
                .bytes_received
                .fetch_add(result.received, Ordering::Relaxed);
        }
        while active.load(Ordering::Relaxed) < cfg.streams * cfg.connections
            && Instant::now() < measure_deadline
        {
            let index = next_connection.fetch_add(1, Ordering::Relaxed);
            let conn = &connections[(index as usize) % connections.len()];
            open_bulk_download(conn.conn.clone(), true, tx.clone(), active.clone());
        }
    }
    let drain_deadline = Instant::now() + DEFAULT_DRAIN_TIMEOUT;
    while active.load(Ordering::Relaxed) != 0 && Instant::now() < drain_deadline {
        if let Some(result) = rx.recv().await {
            if let Some(err) = result.err {
                return Err(err.into());
            }
        }
    }
    Ok(())
}

fn open_bulk_download(
    conn: Connection,
    counts: bool,
    tx: mpsc::Sender<BulkStreamResult>,
    active: Arc<AtomicU64>,
) {
    active.fetch_add(1, Ordering::Relaxed);
    tokio::spawn(async move {
        let result = run_bulk_download_stream(conn).await;
        active.fetch_sub(1, Ordering::Relaxed);
        let _ = tx
            .send(match result {
                Ok(received) => BulkStreamResult {
                    counts,
                    received,
                    err: None,
                },
                Err(err) => BulkStreamResult {
                    counts,
                    received: 0,
                    err: Some(err.to_string()),
                },
            })
            .await;
    });
}

async fn run_bulk_download_stream(conn: Connection) -> Result<u64, AnyError> {
    let (mut send, mut recv) = conn.open_bi().await?;
    send.finish()?;
    copy_and_count(&mut recv).await
}

async fn run_fixed_bulk(
    cfg: &Config,
    connections: &[ConnectionState],
    counters: Arc<MeasuredCounters>,
) -> Result<(), AnyError> {
    if !cfg.total_bytes.set {
        return Err("fixed bulk requires --total-bytes for quinn client".into());
    }
    let per_stream = cfg.total_bytes.value / cfg.streams;
    let remainder = cfg.total_bytes.value % cfg.streams;
    let mut handles = Vec::with_capacity(int_cap(cfg.streams));
    for i in 0..cfg.streams {
        let target_bytes = per_stream + u64::from(i < remainder);
        let conn = connections[(i as usize) % connections.len()].conn.clone();
        let direction = cfg.direction.clone();
        let counters = counters.clone();
        handles.push(tokio::spawn(async move {
            let (sent, received) = run_fixed_bulk_stream(conn, &direction, target_bytes).await?;
            counters.bytes_sent.fetch_add(sent, Ordering::Relaxed);
            counters
                .bytes_received
                .fetch_add(received, Ordering::Relaxed);
            Ok::<(), AnyError>(())
        }));
    }
    for handle in handles {
        handle.await??;
    }
    Ok(())
}

async fn run_fixed_bulk_stream(
    conn: Connection,
    direction: &str,
    target_bytes: u64,
) -> Result<(u64, u64), AnyError> {
    let (mut send, mut recv) = conn.open_bi().await?;
    if direction == DIRECTION_UPLOAD {
        let sent = write_n(&mut send, target_bytes).await?;
        send.finish()?;
        return Ok((sent, 0));
    }
    send.finish()?;
    let received = copy_and_count(&mut recv).await?;
    Ok((0, received))
}

async fn run_rr(
    cfg: &Config,
    connections: &[ConnectionState],
    counters: Arc<MeasuredCounters>,
) -> Result<(), AnyError> {
    let measure_start = Instant::now() + cfg.warmup;
    let measure_deadline = measure_start + cfg.duration;
    let (tx, mut rx) = mpsc::channel(int_cap(
        cfg.requests_in_flight * connections.len() as u64 + 64,
    ));
    let active = Arc::new(AtomicU64::new(0));
    let started = AtomicU64::new(0);
    let mut next_connection = 0_u64;

    for c in connections {
        for _ in 0..cfg.requests_in_flight {
            open_rr_stream(
                c.conn.clone(),
                cfg.request_bytes,
                cfg.requests.set || Instant::now() > measure_start,
                tx.clone(),
                active.clone(),
                &started,
            );
        }
    }

    loop {
        if !cfg.requests.set && Instant::now() > measure_deadline {
            break;
        }
        if cfg.requests.set
            && started.load(Ordering::Relaxed) >= cfg.requests.value
            && active.load(Ordering::Relaxed) == 0
        {
            break;
        }
        let result = rx.recv().await.ok_or("rr result channel closed")?;
        active.fetch_sub(1, Ordering::Relaxed);
        if let Some(err) = result.err {
            return Err(err.into());
        }
        if result.counts && Instant::now() > measure_start {
            counters
                .bytes_sent
                .fetch_add(cfg.request_bytes, Ordering::Relaxed);
            counters
                .bytes_received
                .fetch_add(result.received, Ordering::Relaxed);
            counters.requests_completed.fetch_add(1, Ordering::Relaxed);
            counters.latencies.lock().await.push(result.latency);
        }
        while active.load(Ordering::Relaxed) < cfg.requests_in_flight * connections.len() as u64 {
            if cfg.requests.set && started.load(Ordering::Relaxed) >= cfg.requests.value {
                break;
            }
            if !cfg.requests.set && Instant::now() > measure_deadline {
                break;
            }
            let c = &connections[(next_connection as usize) % connections.len()];
            next_connection += 1;
            open_rr_stream(
                c.conn.clone(),
                cfg.request_bytes,
                cfg.requests.set || Instant::now() > measure_start,
                tx.clone(),
                active.clone(),
                &started,
            );
        }
    }
    Ok(())
}

fn open_rr_stream(
    conn: Connection,
    request_bytes: u64,
    counts: bool,
    tx: mpsc::Sender<RRStreamResult>,
    active: Arc<AtomicU64>,
    started: &AtomicU64,
) {
    active.fetch_add(1, Ordering::Relaxed);
    started.fetch_add(1, Ordering::Relaxed);
    tokio::spawn(async move {
        let result = run_request_response_stream(conn, request_bytes).await;
        let _ = tx
            .send(match result {
                Ok((latency, received)) => RRStreamResult {
                    counts,
                    latency,
                    received,
                    err: None,
                },
                Err(err) => RRStreamResult {
                    counts,
                    latency: Duration::ZERO,
                    received: 0,
                    err: Some(err.to_string()),
                },
            })
            .await;
    });
}

async fn run_crr(
    cfg: &Config,
    start: &SessionStart,
    counters: Arc<MeasuredCounters>,
) -> Result<(), AnyError> {
    let measure_start = Instant::now() + cfg.warmup;
    let measure_deadline = measure_start + cfg.duration;
    let (tx, mut rx) = mpsc::channel(int_cap(cfg.connections + 64));
    let sem = Arc::new(tokio::sync::Semaphore::new(int_cap(cfg.connections)));
    let started = Arc::new(AtomicU64::new(0));
    let active = Arc::new(AtomicU64::new(0));

    for _ in 0..cfg.connections {
        if !start_one_crr(
            cfg,
            start,
            cfg.requests.set || Instant::now() > measure_start,
            tx.clone(),
            sem.clone(),
            started.clone(),
            active.clone(),
            counters.clone(),
        ) {
            break;
        }
    }

    loop {
        if !cfg.requests.set && Instant::now() > measure_deadline {
            break;
        }
        let result = rx.recv().await.ok_or("crr result channel closed")?;
        active.fetch_sub(1, Ordering::Relaxed);
        if let Some(err) = result.err {
            return Err(err.into());
        }
        if result.counts && Instant::now() > measure_start {
            counters
                .bytes_sent
                .fetch_add(cfg.request_bytes, Ordering::Relaxed);
            counters
                .bytes_received
                .fetch_add(result.received, Ordering::Relaxed);
            counters.requests_completed.fetch_add(1, Ordering::Relaxed);
            counters.latencies.lock().await.push(result.latency);
        }
        if cfg.requests.set && started.load(Ordering::Relaxed) >= cfg.requests.value {
            if active.load(Ordering::Relaxed) == 0 {
                break;
            }
            continue;
        }
        if !cfg.requests.set && Instant::now() > measure_deadline {
            continue;
        }
        let _ = start_one_crr(
            cfg,
            start,
            cfg.requests.set || Instant::now() > measure_start,
            tx.clone(),
            sem.clone(),
            started.clone(),
            active.clone(),
            counters.clone(),
        );
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn start_one_crr(
    cfg: &Config,
    start: &SessionStart,
    counts: bool,
    tx: mpsc::Sender<RRStreamResult>,
    sem: Arc<tokio::sync::Semaphore>,
    started: Arc<AtomicU64>,
    active: Arc<AtomicU64>,
    counters: Arc<MeasuredCounters>,
) -> bool {
    if cfg.requests.set && started.load(Ordering::Relaxed) >= cfg.requests.value {
        return false;
    }
    let cfg = cfg.clone();
    let start = start.clone();
    started.fetch_add(1, Ordering::Relaxed);
    active.fetch_add(1, Ordering::Relaxed);
    tokio::spawn(async move {
        let _permit = sem.acquire_owned().await.expect("semaphore closed");
        let result = async {
            let connections = open_connections(&cfg, &start, 1)
                .await
                .map_err(|err| format!("quinn crr setup: {err}"))?;
            let conn = connections[0].conn.clone();
            let out = run_request_response_stream(conn, cfg.request_bytes).await;
            for c in connections {
                c.conn.close(0u32.into(), b"done");
            }
            out
        }
        .await;
        let mut message = RRStreamResult::default();
        message.counts = counts;
        match result {
            Ok((latency, received)) => {
                message.latency = latency;
                message.received = received;
            }
            Err(err) => {
                let err = err.to_string();
                if is_timed_crr_setup_error(&cfg, &err) {
                    counters
                        .skipped_setup_errors
                        .fetch_add(1, Ordering::Relaxed);
                    time::sleep(Duration::from_millis(2)).await;
                } else {
                    message.err = Some(err);
                }
            }
        }
        let _ = tx.send(message).await;
    });
    true
}

fn is_timed_crr_setup_error(cfg: &Config, err: &str) -> bool {
    !cfg.requests.set
        && err.starts_with("quinn crr setup:")
        && (err.contains("refused")
            || err.contains("deadline has elapsed")
            || err.contains("timed out"))
}

async fn run_request_response_stream(
    conn: Connection,
    request_bytes: u64,
) -> Result<(Duration, u64), AnyError> {
    let start = Instant::now();
    let (mut send, mut recv) = conn.open_bi().await?;
    write_n(&mut send, request_bytes).await?;
    send.finish()?;
    let received = copy_and_count(&mut recv).await?;
    Ok((start.elapsed(), received))
}

async fn read_first_complete(connections: &[ConnectionState]) -> Result<SessionComplete, AnyError> {
    for c in connections {
        let mut control = c.control_recv.lock().await;
        let read = time::timeout(DEFAULT_DRAIN_TIMEOUT, read_control_message(&mut control)).await;
        if let Ok(Ok(msg)) = read {
            if msg.message_type == MESSAGE_SESSION_COMPLETE {
                return Ok(msg.complete);
            }
        }
    }
    Err("no session_complete received".into())
}

async fn read_control_message(recv: &mut RecvStream) -> Result<ControlMessage, AnyError> {
    let mut header = [0_u8; 5];
    read_exact_stream(recv, &mut header).await?;
    let len = u32::from_be_bytes(header[1..5].try_into().unwrap()) as usize;
    let mut payload = vec![0_u8; len];
    read_exact_stream(recv, &mut payload).await?;
    let mut msg = ControlMessage {
        message_type: header[0],
        ready: false,
        error_reason: String::new(),
        start: None,
        complete: SessionComplete::default(),
    };
    match header[0] {
        MESSAGE_SESSION_START => {
            if payload.len() != 79 {
                return Err("malformed session_start".into());
            }
            let version = u32::from_be_bytes(payload[0..4].try_into().unwrap());
            if version != PROTOCOL_VERSION {
                return Err(format!("unsupported protocol version: {version}").into());
            }
            let flags = payload[22];
            let start = SessionStart {
                mode: mode_from_code(payload[4]).to_string(),
                direction: direction_from_code(payload[5]).to_string(),
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
            if ![MODE_BULK, MODE_RR, MODE_CRR].contains(&start.mode.as_str())
                || ![DIRECTION_UPLOAD, DIRECTION_DOWNLOAD].contains(&start.direction.as_str())
                || start.streams == 0
                || start.connections == 0
                || start.requests_in_flight == 0
            {
                return Err("malformed session_start".into());
            }
            msg.start = Some(start);
        }
        MESSAGE_SESSION_READY => {
            if payload.len() != 4 {
                return Err("malformed session_ready".into());
            }
            msg.ready = u32::from_be_bytes(payload[0..4].try_into().unwrap()) == PROTOCOL_VERSION;
        }
        MESSAGE_SESSION_ERROR => {
            if payload.len() < 4 {
                return Err("malformed session_error".into());
            }
            let n = u32::from_be_bytes(payload[0..4].try_into().unwrap()) as usize;
            if payload[4..].len() != n {
                return Err("malformed session_error length".into());
            }
            msg.error_reason = String::from_utf8(payload[4..].to_vec())?;
        }
        MESSAGE_SESSION_COMPLETE => {
            if payload.len() != 24 {
                return Err("malformed session_complete".into());
            }
            msg.complete = SessionComplete {
                bytes_sent: u64::from_be_bytes(payload[0..8].try_into().unwrap()),
                bytes_received: u64::from_be_bytes(payload[8..16].try_into().unwrap()),
                requests_completed: u64::from_be_bytes(payload[16..24].try_into().unwrap()),
            };
        }
        _ => return Err(format!("unknown control message type {}", header[0]).into()),
    }
    Ok(msg)
}

async fn read_exact_stream(recv: &mut RecvStream, mut out: &mut [u8]) -> Result<(), AnyError> {
    while !out.is_empty() {
        let n = recv.read(out).await?.ok_or("unexpected end of stream")?;
        if n == 0 {
            return Err("unexpected zero-byte stream read".into());
        }
        let tmp = out;
        out = &mut tmp[n..];
    }
    Ok(())
}

fn encode_session_start(start: &SessionStart) -> Vec<u8> {
    let mut payload = Vec::with_capacity(79);
    append_u32(&mut payload, PROTOCOL_VERSION);
    payload.push(mode_code(&start.mode));
    payload.push(direction_code(&start.direction));
    append_u64(&mut payload, start.request_bytes);
    append_u64(&mut payload, start.response_bytes);
    let mut flags = 0_u8;
    if start.total_bytes.set {
        flags |= 0x01;
    }
    if start.requests.set {
        flags |= 0x02;
    }
    payload.push(flags);
    append_u64(&mut payload, start.total_bytes.value);
    append_u64(&mut payload, start.requests.value);
    append_u64(&mut payload, start.warmup.as_micros() as u64);
    append_u64(&mut payload, start.duration.as_micros() as u64);
    append_u64(&mut payload, start.streams);
    append_u64(&mut payload, start.connections);
    append_u64(&mut payload, start.requests_in_flight);
    frame_control_message(MESSAGE_SESSION_START, payload)
}

fn encode_session_ready() -> Vec<u8> {
    let mut payload = Vec::with_capacity(4);
    append_u32(&mut payload, PROTOCOL_VERSION);
    frame_control_message(MESSAGE_SESSION_READY, payload)
}

fn encode_session_error(reason: &str) -> Vec<u8> {
    let mut payload = Vec::with_capacity(4 + reason.len());
    append_u32(&mut payload, reason.len() as u32);
    payload.extend_from_slice(reason.as_bytes());
    frame_control_message(MESSAGE_SESSION_ERROR, payload)
}

fn encode_session_complete(complete: SessionComplete) -> Vec<u8> {
    let mut payload = Vec::with_capacity(24);
    append_u64(&mut payload, complete.bytes_sent);
    append_u64(&mut payload, complete.bytes_received);
    append_u64(&mut payload, complete.requests_completed);
    frame_control_message(MESSAGE_SESSION_COMPLETE, payload)
}

fn frame_control_message(message_type: u8, payload: Vec<u8>) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + payload.len());
    out.push(message_type);
    append_u32(&mut out, payload.len() as u32);
    out.extend_from_slice(&payload);
    out
}

async fn send_control_message(mut send: SendStream, data: Vec<u8>) -> Result<(), AnyError> {
    send.write_all(&data).await?;
    send.finish()?;
    Ok(())
}

fn mode_code(mode: &str) -> u8 {
    match mode {
        MODE_RR => 1,
        MODE_CRR => 2,
        _ => 0,
    }
}

fn direction_code(direction: &str) -> u8 {
    u8::from(direction == DIRECTION_DOWNLOAD)
}

fn mode_from_code(value: u8) -> &'static str {
    match value {
        0 => MODE_BULK,
        1 => MODE_RR,
        2 => MODE_CRR,
        _ => "unknown",
    }
}

fn direction_from_code(value: u8) -> &'static str {
    match value {
        0 => DIRECTION_UPLOAD,
        1 => DIRECTION_DOWNLOAD,
        _ => "unknown",
    }
}

fn append_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn append_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}

async fn write_n(send: &mut SendStream, n: u64) -> Result<u64, AnyError> {
    let buf = vec![0x5a_u8; WRITE_CHUNK_SIZE];
    let mut sent = 0_u64;
    while sent < n {
        let chunk = cmp::min(buf.len() as u64, n - sent) as usize;
        send.write_all(&buf[..chunk]).await?;
        sent += chunk as u64;
    }
    Ok(sent)
}

async fn copy_and_count(recv: &mut RecvStream) -> Result<u64, AnyError> {
    let mut total = 0_u64;
    while let Some(chunk) = recv.read_chunk(READ_CHUNK_SIZE, true).await? {
        total += chunk.bytes.len() as u64;
    }
    Ok(total)
}

fn finalize_summary(summary: &mut RunSummary) {
    if summary.elapsed_ms == 0 {
        summary.elapsed_ms = summary.warmup_ms;
    }
    let seconds = (summary.elapsed_ms as f64 / 1000.0).max(0.001);
    let total_bytes = summary.bytes_sent + summary.bytes_received;
    summary.throughput_mib_per_s = total_bytes as f64 / (1024.0 * 1024.0) / seconds;
    summary.throughput_gbit_per_s = (total_bytes as f64 * 8.0) / 1_000_000_000.0 / seconds;
    summary.requests_per_s = summary.requests_completed as f64 / seconds;
}

fn summarize_latency(samples: &[Duration]) -> LatencySummary {
    if samples.is_empty() {
        return LatencySummary::default();
    }
    let mut micros: Vec<u64> = samples
        .iter()
        .map(|sample| sample.as_micros() as u64)
        .collect();
    micros.sort_unstable();
    let total: u64 = micros.iter().sum();
    LatencySummary {
        min_us: micros[0],
        avg_us: total / micros.len() as u64,
        p50_us: percentile(&micros, 50.0),
        p90_us: percentile(&micros, 90.0),
        p99_us: percentile(&micros, 99.0),
        max_us: micros[micros.len() - 1],
    }
}

fn percentile(sorted: &[u64], pct: f64) -> u64 {
    let rank = ((pct / 100.0) * sorted.len() as f64).ceil() as usize;
    sorted[rank.saturating_sub(1).min(sorted.len() - 1)]
}

fn emit_summary(summary: &RunSummary, json_out: Option<&str>) -> Result<(), AnyError> {
    println!(
        "status={} mode={} cc={} direction={} throughput_mib/s={:.3} throughput_gbit/s={:.3} requests/s={:.3}",
        summary.status,
        summary.mode,
        summary.congestion_control,
        summary.direction,
        summary.throughput_mib_per_s,
        summary.throughput_gbit_per_s,
        summary.requests_per_s
    );
    if let Some(path) = json_out {
        fs::write(path, serde_json::to_vec(summary)?)?;
    }
    Ok(())
}

fn load_certs(path: &str) -> Result<Vec<CertificateDer<'static>>, AnyError> {
    let bytes = fs::read(path)?;
    let mut reader = io::Cursor::new(bytes);
    Ok(rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>()?)
}

fn load_private_key(path: &str) -> Result<PrivateKeyDer<'static>, AnyError> {
    let bytes = fs::read(Path::new(path))?;
    let mut reader = io::Cursor::new(bytes.clone());
    if let Some(key) = rustls_pemfile::private_key(&mut reader)? {
        return Ok(key);
    }
    Ok(PrivateKeyDer::try_from(bytes)?)
}

fn duration_millis(duration: Duration) -> i64 {
    duration.as_millis().try_into().unwrap_or(i64::MAX)
}

fn int_cap(value: u64) -> usize {
    value.min(usize::MAX as u64) as usize
}

fn is_zero(value: &u64) -> bool {
    *value == 0
}

#[derive(Debug)]
struct SkipServerVerification(Arc<CryptoProvider>);

impl SkipServerVerification {
    fn new() -> Arc<Self> {
        Arc::new(Self(Arc::new(rustls::crypto::ring::default_provider())))
    }
}

impl ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

use msquic_async::{msquic, Connection, Listener, Stream, StreamType};
use serde::Serialize;
use std::cmp;
use std::env;
use std::fs;
use std::future::poll_fn;
use std::io::{self, Write};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, Mutex};
use tokio::time;

const PROTOCOL_VERSION: u32 = 3;
const APPLICATION_PROTOCOL: &[u8] = b"coquic-perf/1";
const TRANSFER_CONNECTION_WINDOW: u32 = 32 * 1024 * 1024;
const TRANSFER_STREAM_WINDOW: u32 = 16 * 1024 * 1024;
const SETUP_TIMEOUT: Duration = Duration::from_secs(5);
const SERVER_READY_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_DRAIN_TIMEOUT: Duration = Duration::from_secs(2);
const STREAM_IO_TIMEOUT: Duration = Duration::from_secs(10);
const STREAM_FINISH_TIMEOUT: Duration = Duration::from_secs(10);
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
const DIRECTION_STAY: &str = "stay";

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
    control_recv: Arc<Mutex<Stream>>,
    conn: Connection,
    _configuration: Arc<msquic::Configuration>,
    _registration: Arc<msquic::Registration>,
}

struct CrrConnectionState {
    conn: Connection,
    _configuration: Arc<msquic::Configuration>,
    _registration: Arc<msquic::Registration>,
}

#[derive(Clone)]
struct ClientMsQuicContext {
    registration: Arc<msquic::Registration>,
    configuration: Arc<msquic::Configuration>,
}

#[derive(Default)]
struct RRStreamResult {
    counts: bool,
    skipped_setup: bool,
    latency: Duration,
    received: u64,
    err: Option<String>,
}

struct BulkStreamResult {
    counts: bool,
    received: u64,
    err: Option<String>,
}

struct ServerSession {
    control_send: Mutex<Stream>,
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
    let mut args: Vec<String> = env::args().collect();
    if args.len() < 2 || (args[1] != "client" && args[1] != "server") {
        eprintln!("usage: msquic-perf [client|server] [options]");
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
    let _ = io::stdout().flush();
    let _ = io::stderr().flush();
    let exit_code = if summary.status == "ok" { 0 } else { 1 };
    immediate_exit(exit_code);
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
    if cfg.direction != DIRECTION_UPLOAD
        && cfg.direction != DIRECTION_DOWNLOAD
        && cfg.direction != DIRECTION_STAY
    {
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
    let registration = msquic_registration()?;
    let configuration = msquic_configuration(
        &registration,
        Some((&cfg.certificate_chain, &cfg.private_key)),
        cfg.verify_peer,
        &cfg.congestion_control,
    )?;
    let listener = Listener::new(&registration, configuration)?;
    let alpn = [msquic::BufferRef::from(APPLICATION_PROTOCOL)];
    let addr: SocketAddr = format!("{}:{}", cfg.host, cfg.port).parse()?;
    listener.start(&alpn, Some(addr))?;

    while let Ok(conn) = listener.accept().await {
        tokio::spawn(async move {
            if let Err(err) = handle_server_connection(conn).await {
                eprintln!("msquic server connection failed: {err}");
            }
        });
    }
    Ok(())
}

async fn handle_server_connection(conn: Connection) -> Result<(), AnyError> {
    let mut control_stream = conn.accept_inbound_stream().await?;
    let msg = read_control_message(&mut control_stream).await?;
    let Some(start) = msg.start else {
        let _ = send_control_message(
            control_stream,
            encode_session_error("expected session_start"),
        )
        .await;
        let _ = conn.shutdown(1);
        return Ok(());
    };

    let session = Arc::new(ServerSession {
        control_send: Mutex::new(control_stream),
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
        let stream = conn.accept_inbound_stream().await;
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
    mut stream: Stream,
) -> Result<(), AnyError> {
    let received = copy_and_count_with_timeout(&mut stream).await?;
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
        let sent = write_n(&mut stream, response_bytes).await?;
        session.bytes_sent.fetch_add(sent, Ordering::Relaxed);
    }
    finish_stream_write(&mut stream).await?;

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
        finish_stream_write(&mut control).await?;
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
        direction: normalized_direction(&cfg.direction).to_string(),
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

    let client_context = Arc::new(client_msquic_context(cfg)?);
    let mut connections = Vec::new();
    if cfg.mode != MODE_CRR {
        connections = open_connections(cfg, &start, cfg.connections, &client_context).await?;
    }

    let counters = Arc::new(MeasuredCounters::default());
    let run_start = Instant::now();
    let elapsed = match cfg.mode.as_str() {
        MODE_BULK => {
            if cfg.direction == DIRECTION_DOWNLOAD && !cfg.total_bytes.set {
                let bulk_timeout = cfg.warmup + cfg.duration + DEFAULT_DRAIN_TIMEOUT;
                timeout_any(
                    "msquic timed bulk download",
                    bulk_timeout,
                    run_timed_bulk_download(cfg, &connections, counters.clone()),
                )
                .await?;
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
            run_crr(cfg, &start, counters.clone(), client_context).await?;
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
    if cfg.mode == MODE_BULK && expects_session_complete(cfg) {
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
    std::mem::forget(connections);
    Ok(summary)
}

fn new_run_summary(cfg: &Config) -> RunSummary {
    RunSummary {
        schema_version: 1,
        status: "ok".to_string(),
        mode: cfg.mode.clone(),
        direction: normalized_direction(&cfg.direction).to_string(),
        backend: cfg.io_backend.clone(),
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

fn client_msquic_context(cfg: &Config) -> Result<ClientMsQuicContext, AnyError> {
    let registration = Arc::new(msquic_registration()?);
    let configuration = Arc::new(msquic_configuration(
        &registration,
        None,
        cfg.verify_peer,
        &cfg.congestion_control,
    )?);
    Ok(ClientMsQuicContext {
        registration,
        configuration,
    })
}

fn msquic_registration() -> Result<msquic::Registration, AnyError> {
    Ok(msquic::Registration::new(
        &msquic::RegistrationConfig::new()
            .set_app_name("coquic-msquic-perf".to_string())
            .set_execution_profile(msquic::ExecutionProfile::MaxThroughput),
    )?)
}

fn msquic_configuration(
    registration: &msquic::Registration,
    certificate: Option<(&str, &str)>,
    verify_peer: bool,
    congestion_control: &str,
) -> Result<msquic::Configuration, AnyError> {
    let alpn = [msquic::BufferRef::from(APPLICATION_PROTOCOL)];
    let mut settings = msquic::Settings::new()
        .set_IdleTimeoutMs(30_000)
        .set_HandshakeIdleTimeoutMs(10_000)
        .set_ConnFlowControlWindow(TRANSFER_CONNECTION_WINDOW)
        .set_StreamRecvWindowDefault(TRANSFER_STREAM_WINDOW)
        .set_StreamRecvWindowBidiLocalDefault(TRANSFER_STREAM_WINDOW)
        .set_StreamRecvWindowBidiRemoteDefault(TRANSFER_STREAM_WINDOW)
        .set_PeerBidiStreamCount(4096)
        .set_PeerUnidiStreamCount(0)
        .set_StreamMultiReceiveEnabled()
        .set_PacingEnabled();
    match congestion_control {
        "default" | "cubic" => {
            settings = settings.set_CongestionControlAlgorithm(
                msquic::ffi::QUIC_CONGESTION_CONTROL_ALGORITHM_QUIC_CONGESTION_CONTROL_ALGORITHM_CUBIC
                    as u16,
            );
        }
        "bbr" => {
            settings = settings.set_CongestionControlAlgorithm(
                msquic::ffi::QUIC_CONGESTION_CONTROL_ALGORITHM_QUIC_CONGESTION_CONTROL_ALGORITHM_BBR
                    as u16,
            );
        }
        other => {
            return Err(format!("msquic-perf unsupported congestion-control label: {other}").into())
        }
    }

    let configuration = msquic::Configuration::open(registration, &alpn, Some(&settings))?;
    let credential = if let Some((cert_path, key_path)) = certificate {
        msquic::CredentialConfig::new().set_credential(msquic::Credential::CertificateFile(
            msquic::CertificateFile::new(key_path.to_string(), cert_path.to_string()),
        ))
    } else if verify_peer {
        msquic::CredentialConfig::new_client()
    } else {
        msquic::CredentialConfig::new_client()
            .set_credential_flags(msquic::CredentialFlags::NO_CERTIFICATE_VALIDATION)
    };
    configuration.load_credential(&credential)?;
    Ok(configuration)
}

async fn open_connections(
    cfg: &Config,
    start: &SessionStart,
    count: u64,
    context: &ClientMsQuicContext,
) -> Result<Vec<ConnectionState>, AnyError> {
    let mut out = Vec::with_capacity(int_cap(count));
    for _ in 0..count {
        let conn = Connection::new(&context.registration)?;
        timeout_result(
            "msquic connection start",
            SETUP_TIMEOUT,
            conn.start(&context.configuration, &cfg.host, cfg.port),
        )
        .await?;
        let mut control =
            open_bidi_stream(&conn, "msquic control stream open", SETUP_TIMEOUT).await?;
        timeout_result(
            "msquic control stream write",
            SETUP_TIMEOUT,
            control.write_all(&encode_session_start(start)),
        )
        .await?;
        timeout_result(
            "msquic control stream finish",
            SETUP_TIMEOUT,
            poll_fn(|cx| control.poll_finish_write(cx)),
        )
        .await?;
        wait_for_ready(&mut control).await?;
        out.push(ConnectionState {
            control_recv: Arc::new(Mutex::new(control)),
            conn,
            _configuration: context.configuration.clone(),
            _registration: context.registration.clone(),
        });
    }
    Ok(out)
}

async fn open_crr_connection(
    cfg: &Config,
    start: &SessionStart,
    context: &ClientMsQuicContext,
) -> Result<CrrConnectionState, AnyError> {
    let conn = Connection::new(&context.registration)?;
    conn.set_share_binding(true)
        .map_err(|err| format!("msquic crr share udp binding: {err} ({err:?})"))?;
    timeout_result(
        "msquic crr connection start",
        SETUP_TIMEOUT,
        conn.start(&context.configuration, &cfg.host, cfg.port),
    )
    .await?;
    let mut control =
        open_bidi_stream(&conn, "msquic crr control stream open", SETUP_TIMEOUT).await?;
    timeout_result(
        "msquic crr control stream write",
        SETUP_TIMEOUT,
        control.write_all(&encode_session_start(start)),
    )
    .await?;
    timeout_result(
        "msquic crr control stream finish",
        SETUP_TIMEOUT,
        poll_fn(|cx| control.poll_finish_write(cx)),
    )
    .await?;
    wait_for_ready(&mut control).await?;
    let _ = control.abort_read(0);
    Ok(CrrConnectionState {
        conn,
        _configuration: context.configuration.clone(),
        _registration: context.registration.clone(),
    })
}

async fn close_crr_connection(connection: CrrConnectionState) {
    let _ = time::timeout(
        DEFAULT_DRAIN_TIMEOUT,
        poll_fn(|cx| connection.conn.poll_shutdown(cx, 0)),
    )
    .await;
}

async fn wait_for_ready(control: &mut Stream) -> Result<(), AnyError> {
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
    let target_active = cfg.streams * cfg.connections;
    let (tx, mut rx) = mpsc::channel(int_cap(target_active + 64));
    let active = Arc::new(AtomicU64::new(0));
    let next_connection = AtomicU64::new(0);

    for c in connections {
        for _ in 0..cfg.streams {
            open_bulk_download(c.conn.clone(), false, tx.clone(), active.clone());
        }
    }

    time::sleep_until(tokio::time::Instant::from_std(measure_start)).await;
    while Instant::now() < measure_deadline {
        let Some(result) = recv_bulk_result_until(&mut rx, measure_deadline).await? else {
            break;
        };
        if let Some(err) = result.err {
            return Err(err.into());
        }
        if result.counts {
            counters
                .bytes_received
                .fetch_add(result.received, Ordering::Relaxed);
        }
        while active.load(Ordering::Relaxed) < target_active && Instant::now() < measure_deadline {
            let index = next_connection.fetch_add(1, Ordering::Relaxed);
            let conn = &connections[(index as usize) % connections.len()];
            open_bulk_download(conn.conn.clone(), true, tx.clone(), active.clone());
        }
    }
    let drain_deadline = Instant::now() + DEFAULT_DRAIN_TIMEOUT;
    while active.load(Ordering::Relaxed) != 0 && Instant::now() < drain_deadline {
        if let Some(result) = recv_bulk_result_until(&mut rx, drain_deadline).await? {
            if let Some(err) = result.err {
                return Err(err.into());
            }
        } else {
            break;
        }
    }
    Ok(())
}

async fn recv_bulk_result_until(
    rx: &mut mpsc::Receiver<BulkStreamResult>,
    deadline: Instant,
) -> Result<Option<BulkStreamResult>, AnyError> {
    if Instant::now() >= deadline {
        return Ok(None);
    }
    match time::timeout_at(tokio::time::Instant::from_std(deadline), rx.recv()).await {
        Ok(Some(result)) => Ok(Some(result)),
        Ok(None) => Err("bulk result channel closed".into()),
        Err(_) => Ok(None),
    }
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
    let mut stream = open_bidi_stream(&conn, "msquic data stream open", SETUP_TIMEOUT).await?;
    finish_stream_write(&mut stream).await?;
    copy_and_count_with_timeout(&mut stream).await
}

async fn run_fixed_bulk(
    cfg: &Config,
    connections: &[ConnectionState],
    counters: Arc<MeasuredCounters>,
) -> Result<(), AnyError> {
    if !cfg.total_bytes.set {
        return Err("fixed bulk requires --total-bytes for msquic client".into());
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
    let mut stream = open_bidi_stream(&conn, "msquic data stream open", SETUP_TIMEOUT).await?;
    if direction == DIRECTION_UPLOAD {
        let sent = write_n(&mut stream, target_bytes).await?;
        finish_stream_write(&mut stream).await?;
        return Ok((sent, 0));
    }
    finish_stream_write(&mut stream).await?;
    let received = copy_and_count_with_timeout(&mut stream).await?;
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
        if result.skipped_setup {
            // Timed CRR setup churn is exposed through skipped_setup_errors.
        } else if result.counts && Instant::now() > measure_start {
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
                    skipped_setup: false,
                    latency,
                    received,
                    err: None,
                },
                Err(err) => RRStreamResult {
                    counts,
                    skipped_setup: false,
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
    context: Arc<ClientMsQuicContext>,
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
            context.clone(),
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
            context.clone(),
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
    context: Arc<ClientMsQuicContext>,
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
            let connection = open_crr_connection(&cfg, &start, &context).await?;
            let conn = connection.conn.clone();
            let out = run_request_response_stream(conn, cfg.request_bytes).await;
            close_crr_connection(connection).await;
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
                    message.skipped_setup = true;
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
    if cfg.requests.set {
        return false;
    }
    let is_setup = err.starts_with("msquic crr connection start")
        || err.starts_with("msquic crr control stream");
    is_setup
        && (err.contains("QUIC_STATUS_ADDRESS_IN_USE")
            || err.contains("ADDRESS_IN_USE")
            || err.contains("QUIC_STATUS_CONNECTION_REFUSED")
            || err.contains("refused")
            || err.contains("timed out after"))
}

async fn run_request_response_stream(
    conn: Connection,
    request_bytes: u64,
) -> Result<(Duration, u64), AnyError> {
    let start = Instant::now();
    let mut stream = open_bidi_stream(&conn, "msquic data stream open", SETUP_TIMEOUT).await?;
    write_n_with_timeout(&mut stream, request_bytes).await?;
    finish_stream_write(&mut stream).await?;
    let received = copy_and_count_with_timeout(&mut stream).await?;
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

async fn read_control_message(recv: &mut Stream) -> Result<ControlMessage, AnyError> {
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

async fn read_exact_stream(recv: &mut Stream, mut out: &mut [u8]) -> Result<(), AnyError> {
    while !out.is_empty() {
        let n = recv.read(out).await?;
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

async fn send_control_message(mut send: Stream, data: Vec<u8>) -> Result<(), AnyError> {
    send.write_all(&data).await?;
    finish_stream_write(&mut send).await?;
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
    u8::from(normalized_direction(direction) == DIRECTION_DOWNLOAD)
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

fn normalized_direction(direction: &str) -> &'static str {
    if direction == DIRECTION_UPLOAD {
        DIRECTION_UPLOAD
    } else {
        DIRECTION_DOWNLOAD
    }
}

fn append_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn append_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}

async fn write_n(send: &mut Stream, n: u64) -> Result<u64, AnyError> {
    let buf = vec![0x5a_u8; WRITE_CHUNK_SIZE];
    let mut sent = 0_u64;
    while sent < n {
        let chunk = cmp::min(buf.len() as u64, n - sent) as usize;
        send.write_all(&buf[..chunk]).await?;
        sent += chunk as u64;
    }
    Ok(sent)
}

async fn write_n_with_timeout(send: &mut Stream, n: u64) -> Result<u64, AnyError> {
    timeout_any("msquic stream write", STREAM_IO_TIMEOUT, write_n(send, n)).await
}

async fn open_bidi_stream(
    conn: &Connection,
    label: &str,
    timeout: Duration,
) -> Result<Stream, AnyError> {
    timeout_result(
        label,
        timeout,
        conn.open_outbound_stream(StreamType::Bidirectional, false),
    )
    .await
}

async fn finish_stream_write(stream: &mut Stream) -> Result<(), AnyError> {
    timeout_result(
        "msquic stream finish write",
        STREAM_FINISH_TIMEOUT,
        poll_fn(|cx| stream.poll_finish_write(cx)),
    )
    .await
}

async fn copy_and_count(recv: &mut Stream) -> Result<u64, AnyError> {
    let mut total = 0_u64;
    let mut buf = vec![0_u8; READ_CHUNK_SIZE];
    loop {
        let read = recv.read(&mut buf).await?;
        if read == 0 {
            break;
        }
        total += read as u64;
    }
    Ok(total)
}

async fn copy_and_count_with_timeout(recv: &mut Stream) -> Result<u64, AnyError> {
    timeout_any(
        "msquic stream read",
        STREAM_IO_TIMEOUT,
        copy_and_count(recv),
    )
    .await
}

async fn timeout_result<T, E, F>(label: &str, timeout: Duration, future: F) -> Result<T, AnyError>
where
    E: std::error::Error + std::fmt::Debug + Send + Sync + 'static,
    F: std::future::Future<Output = Result<T, E>>,
{
    match time::timeout(timeout, future).await {
        Ok(result) => result.map_err(|err| format!("{label}: {err} ({err:?})").into()),
        Err(_) => Err(format!("{label} timed out after {} ms", duration_millis(timeout)).into()),
    }
}

async fn timeout_any<T, F>(label: &str, timeout: Duration, future: F) -> Result<T, AnyError>
where
    F: std::future::Future<Output = Result<T, AnyError>>,
{
    match time::timeout(timeout, future).await {
        Ok(result) => result.map_err(|err| format!("{label}: {err}").into()),
        Err(_) => Err(format!("{label} timed out after {} ms", duration_millis(timeout)).into()),
    }
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
    let mut micros: Vec<u64> = samples.iter().map(latency_micros).collect();
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

fn latency_micros(sample: &Duration) -> u64 {
    let nanos = sample.as_nanos();
    if nanos == 0 {
        1
    } else {
        nanos.div_ceil(1_000) as u64
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

fn duration_millis(duration: Duration) -> i64 {
    duration.as_millis().try_into().unwrap_or(i64::MAX)
}

fn int_cap(value: u64) -> usize {
    value.min(usize::MAX as u64) as usize
}

fn is_zero(value: &u64) -> bool {
    *value == 0
}

#[cfg(unix)]
fn immediate_exit(code: i32) -> ! {
    unsafe extern "C" {
        fn _exit(status: std::os::raw::c_int) -> !;
    }
    unsafe { _exit(code as std::os::raw::c_int) }
}

#[cfg(not(unix))]
fn immediate_exit(code: i32) -> ! {
    std::process::exit(code);
}

use bytes::Bytes;
use mio::event::Event;
use std::cell::RefCell;
use std::cmp;
use std::collections::{HashMap, VecDeque};
use std::env;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::rc::Rc;
use std::time::{Duration, Instant};
use tquic::Config as QuicConfig;
use tquic::CongestionControlAlgorithm;
use tquic::Connection;
use tquic::Endpoint;
use tquic::Error as QuicError;
use tquic::PacketInfo;
use tquic::TlsConfig;
use tquic::TransportHandler;
use tquic_tools::QuicSocket;

const PROTOCOL_VERSION: u32 = 1;
const APPLICATION_PROTOCOL: &[u8] = b"coquic-perf/1";
const MAX_BUF_SIZE: usize = 65_536;
const READ_CHUNK_SIZE: usize = 65_536;
const WRITE_CHUNK_SIZE: usize = 32 * 1024;
const TRANSFER_CONNECTION_WINDOW: u64 = 32 * 1024 * 1024;
const TRANSFER_STREAM_WINDOW: u64 = 16 * 1024 * 1024;
const TRANSFER_MAX_STREAMS: u64 = 4096;
const DRIVE_TICK: Duration = Duration::from_millis(5);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const DRAIN_TIMEOUT: Duration = Duration::from_secs(2);
const MODE_BULK: &str = "bulk";
const MODE_RR: &str = "rr";
const MODE_CRR: &str = "crr";
const DIRECTION_UPLOAD: &str = "upload";
const DIRECTION_DOWNLOAD: &str = "download";
const DIRECTION_STAY: &str = "stay";

type AnyError = Box<dyn std::error::Error>;

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

#[derive(Default)]
struct Counters {
    bytes_sent: u64,
    bytes_received: u64,
    requests_completed: u64,
    skipped_setup_errors: u64,
    latencies: Vec<Duration>,
}

#[derive(Default)]
struct ServerCounters {
    bytes_sent: u64,
    bytes_received: u64,
    requests_completed: u64,
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
    failure_reason: String,
    skipped_setup_errors: u64,
}

#[derive(Clone)]
struct CompletedStream {
    conn_index: u64,
    counts: bool,
    request_bytes: u64,
    received: u64,
    latency: Duration,
}

struct ClientStream {
    request_bytes: u64,
    response_bytes: u64,
    request_sent: u64,
    response_received: u64,
    started_at: Instant,
    counts: bool,
}

#[derive(Default)]
struct ClientConn {
    ready: bool,
    closing: bool,
    request_opened: bool,
    streams: HashMap<u64, ClientStream>,
}

#[derive(Default)]
struct ClientShared {
    conns: HashMap<u64, ClientConn>,
    completed: VecDeque<CompletedStream>,
    active_streams: u64,
    started_requests: u64,
    failure: Option<String>,
}

struct ClientHandler {
    shared: Rc<RefCell<ClientShared>>,
}

struct ServerStream {
    header: [u8; 16],
    header_len: usize,
    request_bytes: u64,
    response_bytes: u64,
    request_received: u64,
    response_sent: u64,
    response_fin: bool,
}

impl Default for ServerStream {
    fn default() -> Self {
        Self {
            header: [0; 16],
            header_len: 0,
            request_bytes: 0,
            response_bytes: 0,
            request_received: 0,
            response_sent: 0,
            response_fin: false,
        }
    }
}

#[derive(Default)]
struct ServerConn {
    streams: HashMap<u64, ServerStream>,
}

struct ServerHandler {
    conns: HashMap<u64, ServerConn>,
}

struct EndpointDriver {
    endpoint: Endpoint,
    poll: mio::Poll,
    sock: Rc<QuicSocket>,
    recv_buf: Vec<u8>,
}

struct ClientDriver {
    io: EndpointDriver,
    shared: Rc<RefCell<ClientShared>>,
    remote: SocketAddr,
}

fn main() {
    let mut args: Vec<String> = env::args().collect();
    if args.len() < 2 || (args[1] != "client" && args[1] != "server") {
        eprintln!("usage: tquic-perf [client|server] [options]");
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
        if let Err(err) = run_server(cfg) {
            eprintln!("{err}");
            std::process::exit(1);
        }
        return;
    }

    let mut summary = new_run_summary(&cfg);
    match run_client(&cfg) {
        Ok(done) => summary = done,
        Err(err) => {
            summary.status = "failed".to_string();
            summary.failure_reason = err.to_string();
        }
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
        congestion_control: "default".to_string(),
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

    validate_config(&cfg)?;
    Ok(cfg)
}

fn validate_config(cfg: &Config) -> Result<(), AnyError> {
    if ![MODE_BULK, MODE_RR, MODE_CRR].contains(&cfg.mode.as_str()) {
        return Err(format!("unsupported mode: {}", cfg.mode).into());
    }
    if cfg.io_backend != "socket" {
        return Err("tquic-perf only supports the socket backend".into());
    }
    if !["default", "newreno", "reno", "cubic", "bbr", "bbr3", "copa"]
        .contains(&cfg.congestion_control.as_str())
    {
        return Err(format!(
            "unsupported congestion-control label: {}",
            cfg.congestion_control
        )
        .into());
    }
    if cfg.congestion_control == "newreno" || cfg.congestion_control == "reno" {
        return Err(
            "tquic-perf does not provide Reno; use PERF_CONGESTION_CONTROLS=default".into(),
        );
    }
    if ![DIRECTION_UPLOAD, DIRECTION_DOWNLOAD, DIRECTION_STAY].contains(&cfg.direction.as_str()) {
        return Err(format!("unsupported direction: {}", cfg.direction).into());
    }
    if cfg.mode == MODE_BULK && cfg.direction == DIRECTION_STAY {
        return Err("bulk mode requires upload or download direction".into());
    }
    if cfg.streams == 0 || cfg.connections == 0 || cfg.requests_in_flight == 0 {
        return Err(
            "streams, connections, and requests-in-flight must be greater than zero".into(),
        );
    }
    Ok(())
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

fn run_server(cfg: Config) -> Result<(), AnyError> {
    let local: SocketAddr = format!("{}:{}", cfg.host, cfg.port).parse()?;
    let poll = mio::Poll::new()?;
    let sock = Rc::new(QuicSocket::new(&local, poll.registry())?);
    let handler = ServerHandler {
        conns: HashMap::new(),
    };
    let endpoint = Endpoint::new(
        Box::new(make_quic_config(&cfg, true)?),
        true,
        Box::new(handler),
        sock.clone(),
    );
    let mut driver = EndpointDriver {
        endpoint,
        poll,
        sock,
        recv_buf: vec![0; MAX_BUF_SIZE],
    };

    loop {
        driver.process_once(Duration::from_millis(100))?;
    }
}

fn run_client(cfg: &Config) -> Result<RunSummary, AnyError> {
    let mut summary = new_run_summary(cfg);
    let mut counters = Counters::default();
    let elapsed = match cfg.mode.as_str() {
        MODE_BULK => {
            let mut driver = new_client_driver(cfg)?;
            open_connections(&mut driver, cfg.connections)?;
            let run_start = Instant::now();
            if cfg.total_bytes.set {
                run_fixed_bulk(cfg, &mut driver, &mut counters)?;
                run_start.elapsed()
            } else {
                run_timed_bulk(cfg, &mut driver, &mut counters)?;
                cfg.duration
            }
        }
        MODE_RR => {
            let mut driver = new_client_driver(cfg)?;
            open_connections(&mut driver, cfg.connections)?;
            let run_start = Instant::now();
            run_rr(cfg, &mut driver, &mut counters)?;
            if cfg.requests.set {
                run_start.elapsed()
            } else {
                cfg.duration
            }
        }
        MODE_CRR => {
            let mut driver = new_client_driver(cfg)?;
            let run_start = Instant::now();
            run_crr(cfg, &mut driver, &mut counters)?;
            if cfg.requests.set {
                run_start.elapsed()
            } else {
                cfg.duration
            }
        }
        _ => unreachable!(),
    };

    summary.elapsed_ms = duration_millis(elapsed);
    summary.bytes_sent = counters.bytes_sent;
    summary.bytes_received = counters.bytes_received;
    summary.requests_completed = counters.requests_completed;
    summary.skipped_setup_errors = counters.skipped_setup_errors;
    summary.server_counters = ServerCounters {
        bytes_sent: counters.bytes_received,
        bytes_received: counters.bytes_sent,
        requests_completed: counters.requests_completed,
    };
    summary.latency = summarize_latency(&counters.latencies);
    Ok(summary)
}

fn new_client_driver(cfg: &Config) -> Result<ClientDriver, AnyError> {
    let remote = resolve_remote(&cfg.host, cfg.port)?;
    let local = unspecified_addr(remote);
    let poll = mio::Poll::new()?;
    let sock = Rc::new(QuicSocket::new(&local, poll.registry())?);
    let shared = Rc::new(RefCell::new(ClientShared::default()));
    let handler = ClientHandler {
        shared: shared.clone(),
    };
    let endpoint = Endpoint::new(
        Box::new(make_quic_config(cfg, false)?),
        false,
        Box::new(handler),
        sock.clone(),
    );
    Ok(ClientDriver {
        io: EndpointDriver {
            endpoint,
            poll,
            sock,
            recv_buf: vec![0; MAX_BUF_SIZE],
        },
        shared,
        remote,
    })
}

fn make_quic_config(cfg: &Config, is_server: bool) -> Result<QuicConfig, AnyError> {
    let mut config = QuicConfig::new()?;
    config.set_max_handshake_timeout(10_000);
    config.set_max_idle_timeout(30_000);
    config.enable_dplpmtud(!cfg.disable_pmtud);
    config.set_recv_udp_payload_size(65_527);
    config.set_send_udp_payload_size(1350);
    config.set_max_connection_window(TRANSFER_CONNECTION_WINDOW);
    config.set_max_stream_window(TRANSFER_STREAM_WINDOW);
    config.set_initial_max_data(TRANSFER_CONNECTION_WINDOW);
    config.set_initial_max_stream_data_bidi_local(TRANSFER_STREAM_WINDOW);
    config.set_initial_max_stream_data_bidi_remote(TRANSFER_STREAM_WINDOW);
    config.set_initial_max_streams_bidi(cmp::max(
        TRANSFER_MAX_STREAMS,
        cfg.streams
            .saturating_mul(cfg.connections)
            .saturating_mul(cfg.requests_in_flight),
    ));
    config
        .set_max_concurrent_conns(cmp::max(cfg.connections, 1_000_000).min(u32::MAX as u64) as u32);
    config.set_congestion_control_algorithm(tquic_cc(&cfg.congestion_control)?);

    let alpn = vec![APPLICATION_PROTOCOL.to_vec()];
    let tls_config = if is_server {
        let mut tls_config =
            TlsConfig::new_server_config(&cfg.certificate_chain, &cfg.private_key, alpn, true)?;
        let mut ticket_key = b"coquic tquic perf ticket key".to_vec();
        ticket_key.resize(48, 0);
        tls_config.set_ticket_key(&ticket_key)?;
        tls_config
    } else {
        let mut tls_config = TlsConfig::new_client_config(alpn, false)?;
        tls_config.set_verify(cfg.verify_peer);
        if cfg.verify_peer {
            tls_config.set_ca_certs(&cfg.certificate_chain)?;
        }
        tls_config
    };
    config.set_tls_config(tls_config);
    Ok(config)
}

fn tquic_cc(label: &str) -> Result<CongestionControlAlgorithm, AnyError> {
    match label {
        "default" | "bbr" => Ok(CongestionControlAlgorithm::Bbr),
        "bbr3" => Ok(CongestionControlAlgorithm::Bbr3),
        "cubic" => Ok(CongestionControlAlgorithm::Cubic),
        "copa" => Ok(CongestionControlAlgorithm::Copa),
        other => Err(format!("unsupported tquic congestion-control label: {other}").into()),
    }
}

fn open_connections(driver: &mut ClientDriver, count: u64) -> Result<(), AnyError> {
    for _ in 0..count {
        start_connection(driver)?;
    }
    let deadline = Instant::now() + HANDSHAKE_TIMEOUT;
    while ready_conn_count(driver) < count {
        if Instant::now() >= deadline {
            return Err("tquic connection handshake timed out".into());
        }
        check_client_failure(driver)?;
        driver.io.process_once(DRIVE_TICK)?;
    }
    Ok(())
}

fn start_connection(driver: &mut ClientDriver) -> Result<u64, AnyError> {
    let local = driver.io.sock.local_addr();
    let index =
        driver
            .io
            .endpoint
            .connect(local, driver.remote, Some("localhost"), None, None, None)?;
    Ok(index)
}

fn run_fixed_bulk(
    cfg: &Config,
    driver: &mut ClientDriver,
    counters: &mut Counters,
) -> Result<(), AnyError> {
    if !cfg.total_bytes.set {
        return Err("fixed bulk requires --total-bytes for tquic client".into());
    }
    let ready = ready_conn_indices(driver);
    if ready.is_empty() {
        return Err("no ready tquic connections".into());
    }
    let per_stream = cfg.total_bytes.value / cfg.streams;
    let remainder = cfg.total_bytes.value % cfg.streams;
    for i in 0..cfg.streams {
        let target = per_stream + u64::from(i < remainder);
        let request_bytes = if cfg.direction == DIRECTION_UPLOAD {
            target
        } else {
            0
        };
        let response_bytes = if cfg.direction == DIRECTION_UPLOAD {
            0
        } else {
            target
        };
        let conn_index = ready[(i as usize) % ready.len()];
        open_request_stream(driver, conn_index, request_bytes, response_bytes, true)?;
    }

    let deadline = Instant::now() + cmp::max(cfg.duration * 2, DRAIN_TIMEOUT);
    while active_streams(driver) != 0 {
        if Instant::now() >= deadline {
            return Err("tquic fixed bulk timed out".into());
        }
        driver.io.process_once(DRIVE_TICK)?;
        drain_completed(driver, counters, false, None)?;
        check_client_failure(driver)?;
    }
    Ok(())
}

fn run_timed_bulk(
    cfg: &Config,
    driver: &mut ClientDriver,
    counters: &mut Counters,
) -> Result<(), AnyError> {
    let measure_start = Instant::now() + cfg.warmup;
    let measure_deadline = measure_start + cfg.duration;
    let target_active = cfg.streams * cfg.connections;
    let mut next_conn = 0_u64;
    fill_bulk_streams(
        cfg,
        driver,
        target_active,
        measure_start,
        measure_deadline,
        &mut next_conn,
    )?;
    while Instant::now() < measure_deadline {
        driver.io.process_once(DRIVE_TICK)?;
        drain_completed(driver, counters, false, Some(measure_deadline))?;
        fill_bulk_streams(
            cfg,
            driver,
            target_active,
            measure_start,
            measure_deadline,
            &mut next_conn,
        )?;
        check_client_failure(driver)?;
    }
    Ok(())
}

fn fill_bulk_streams(
    cfg: &Config,
    driver: &mut ClientDriver,
    target_active: u64,
    measure_start: Instant,
    measure_deadline: Instant,
    next_conn: &mut u64,
) -> Result<(), AnyError> {
    let ready = ready_conn_indices(driver);
    if ready.is_empty() {
        return Ok(());
    }
    while active_streams(driver) < target_active && Instant::now() < measure_deadline {
        let request_bytes = if cfg.direction == DIRECTION_UPLOAD {
            cmp::max(cfg.request_bytes, cfg.response_bytes)
        } else {
            0
        };
        let response_bytes = if cfg.direction == DIRECTION_UPLOAD {
            0
        } else {
            cfg.response_bytes
        };
        let conn_index = ready[(*next_conn as usize) % ready.len()];
        *next_conn += 1;
        open_request_stream(
            driver,
            conn_index,
            request_bytes,
            response_bytes,
            Instant::now() >= measure_start,
        )?;
    }
    Ok(())
}

fn run_rr(
    cfg: &Config,
    driver: &mut ClientDriver,
    counters: &mut Counters,
) -> Result<(), AnyError> {
    let measure_start = Instant::now() + cfg.warmup;
    let measure_deadline = measure_start + cfg.duration;
    let target_active = cfg.requests_in_flight * cfg.connections;
    let mut next_conn = 0_u64;
    fill_rr_streams(
        cfg,
        driver,
        target_active,
        measure_start,
        measure_deadline,
        &mut next_conn,
    )?;
    loop {
        if rr_done(cfg, driver, measure_deadline) {
            break;
        }
        driver.io.process_once(DRIVE_TICK)?;
        drain_completed(driver, counters, true, Some(measure_deadline))?;
        fill_rr_streams(
            cfg,
            driver,
            target_active,
            measure_start,
            measure_deadline,
            &mut next_conn,
        )?;
        check_client_failure(driver)?;
    }
    Ok(())
}

fn fill_rr_streams(
    cfg: &Config,
    driver: &mut ClientDriver,
    target_active: u64,
    measure_start: Instant,
    measure_deadline: Instant,
    next_conn: &mut u64,
) -> Result<(), AnyError> {
    let ready = ready_conn_indices(driver);
    if ready.is_empty() {
        return Ok(());
    }
    while active_streams(driver) < target_active {
        if cfg.requests.set && started_requests(driver) >= cfg.requests.value {
            break;
        }
        if !cfg.requests.set && Instant::now() >= measure_deadline {
            break;
        }
        let conn_index = ready[(*next_conn as usize) % ready.len()];
        *next_conn += 1;
        open_request_stream(
            driver,
            conn_index,
            cfg.request_bytes,
            cfg.response_bytes,
            cfg.requests.set || Instant::now() >= measure_start,
        )?;
    }
    Ok(())
}

fn rr_done(cfg: &Config, driver: &ClientDriver, measure_deadline: Instant) -> bool {
    if cfg.requests.set {
        return started_requests(driver) >= cfg.requests.value && active_streams(driver) == 0;
    }
    Instant::now() >= measure_deadline
}

fn run_crr(
    cfg: &Config,
    driver: &mut ClientDriver,
    counters: &mut Counters,
) -> Result<(), AnyError> {
    let measure_start = Instant::now() + cfg.warmup;
    let measure_deadline = measure_start + cfg.duration;
    fill_crr_connections(cfg, driver, measure_deadline)?;
    loop {
        open_ready_crr_requests(cfg, driver, measure_start)?;
        if crr_done(cfg, driver, measure_deadline) {
            break;
        }
        driver.io.process_once(DRIVE_TICK)?;
        let completed = take_completed(driver);
        for done in completed {
            if done.counts && Instant::now() <= measure_deadline {
                counters.bytes_sent += done.request_bytes;
                counters.bytes_received += done.received;
                counters.requests_completed += 1;
                counters.latencies.push(done.latency);
            }
            close_client_connection(driver, done.conn_index);
        }
        fill_crr_connections(cfg, driver, measure_deadline)?;
        check_client_failure(driver)?;
    }
    Ok(())
}

fn fill_crr_connections(
    cfg: &Config,
    driver: &mut ClientDriver,
    measure_deadline: Instant,
) -> Result<(), AnyError> {
    while active_connection_count(driver) < cfg.connections {
        if cfg.requests.set && started_requests(driver) >= cfg.requests.value {
            break;
        }
        if !cfg.requests.set && Instant::now() >= measure_deadline {
            break;
        }
        start_connection(driver)?;
    }
    Ok(())
}

fn open_ready_crr_requests(
    cfg: &Config,
    driver: &mut ClientDriver,
    measure_start: Instant,
) -> Result<(), AnyError> {
    let ready: Vec<u64> = {
        let shared = driver.shared.borrow();
        shared
            .conns
            .iter()
            .filter_map(|(idx, conn)| {
                if conn.ready && !conn.closing && !conn.request_opened {
                    Some(*idx)
                } else {
                    None
                }
            })
            .collect()
    };
    for conn_index in ready {
        if cfg.requests.set && started_requests(driver) >= cfg.requests.value {
            break;
        }
        {
            let mut shared = driver.shared.borrow_mut();
            if let Some(conn) = shared.conns.get_mut(&conn_index) {
                conn.request_opened = true;
            }
        }
        open_request_stream(
            driver,
            conn_index,
            cfg.request_bytes,
            cfg.response_bytes,
            cfg.requests.set || Instant::now() >= measure_start,
        )?;
    }
    Ok(())
}

fn crr_done(cfg: &Config, driver: &ClientDriver, measure_deadline: Instant) -> bool {
    if cfg.requests.set {
        return started_requests(driver) >= cfg.requests.value
            && active_streams(driver) == 0
            && active_connection_count(driver) == 0;
    }
    Instant::now() >= measure_deadline
}

fn open_request_stream(
    driver: &mut ClientDriver,
    conn_index: u64,
    request_bytes: u64,
    response_bytes: u64,
    counts: bool,
) -> Result<(), AnyError> {
    let conn = driver
        .io
        .endpoint
        .conn_get_mut(conn_index)
        .ok_or_else(|| format!("missing tquic connection {conn_index}"))?;
    let stream_id = conn.stream_bidi_new(0, false)?;
    conn.stream_want_read(stream_id, true)?;
    {
        let mut shared = driver.shared.borrow_mut();
        let conn_state = shared
            .conns
            .get_mut(&conn_index)
            .ok_or_else(|| format!("missing tquic connection state {conn_index}"))?;
        conn_state.streams.insert(
            stream_id,
            ClientStream {
                request_bytes,
                response_bytes,
                request_sent: 0,
                response_received: 0,
                started_at: Instant::now(),
                counts,
            },
        );
        shared.active_streams += 1;
        shared.started_requests += 1;
    }
    let mut shared = driver.shared.borrow_mut();
    client_write_stream(&mut shared, conn, stream_id);
    Ok(())
}

fn close_client_connection(driver: &mut ClientDriver, conn_index: u64) {
    if let Some(conn) = driver.io.endpoint.conn_get_mut(conn_index) {
        let _ = conn.close(true, 0, b"done");
    }
    if let Some(conn) = driver.shared.borrow_mut().conns.get_mut(&conn_index) {
        conn.closing = true;
    }
}

fn drain_completed(
    driver: &mut ClientDriver,
    counters: &mut Counters,
    count_requests: bool,
    deadline: Option<Instant>,
) -> Result<(), AnyError> {
    let completed = take_completed(driver);
    for done in completed {
        if !done.counts {
            continue;
        }
        if let Some(deadline) = deadline {
            if Instant::now() > deadline {
                continue;
            }
        }
        counters.bytes_sent += done.request_bytes;
        counters.bytes_received += done.received;
        if count_requests {
            counters.requests_completed += 1;
            counters.latencies.push(done.latency);
        }
    }
    Ok(())
}

fn take_completed(driver: &mut ClientDriver) -> Vec<CompletedStream> {
    let mut shared = driver.shared.borrow_mut();
    shared.completed.drain(..).collect()
}

fn ready_conn_indices(driver: &ClientDriver) -> Vec<u64> {
    let shared = driver.shared.borrow();
    shared
        .conns
        .iter()
        .filter_map(|(idx, conn)| {
            if conn.ready && !conn.closing {
                Some(*idx)
            } else {
                None
            }
        })
        .collect()
}

fn ready_conn_count(driver: &ClientDriver) -> u64 {
    ready_conn_indices(driver).len() as u64
}

fn active_streams(driver: &ClientDriver) -> u64 {
    driver.shared.borrow().active_streams
}

fn started_requests(driver: &ClientDriver) -> u64 {
    driver.shared.borrow().started_requests
}

fn active_connection_count(driver: &ClientDriver) -> u64 {
    driver
        .shared
        .borrow()
        .conns
        .values()
        .filter(|conn| !conn.closing)
        .count() as u64
}

fn check_client_failure(driver: &ClientDriver) -> Result<(), AnyError> {
    if let Some(failure) = driver.shared.borrow().failure.clone() {
        return Err(failure.into());
    }
    Ok(())
}

impl EndpointDriver {
    fn process_once(&mut self, max_wait: Duration) -> Result<(), AnyError> {
        self.endpoint.process_connections()?;
        let timeout = match self.endpoint.timeout() {
            Some(timeout) => cmp_duration(timeout, max_wait),
            None => max_wait,
        };
        let mut events = mio::Events::with_capacity(1024);
        self.poll.poll(&mut events, Some(timeout))?;
        for event in events.iter() {
            if event.is_readable() {
                self.process_read_event(event)?;
            }
        }
        self.endpoint.on_timeout(Instant::now());
        Ok(())
    }

    fn process_read_event(&mut self, event: &Event) -> Result<(), AnyError> {
        loop {
            let (len, local, remote) = match self.sock.recv_from(&mut self.recv_buf, event.token())
            {
                Ok(v) => v,
                Err(err) => {
                    if err.kind() == std::io::ErrorKind::WouldBlock {
                        break;
                    }
                    return Err(format!("socket recv error: {err:?}").into());
                }
            };
            let pkt_info = PacketInfo {
                src: remote,
                dst: local,
                time: Instant::now(),
            };
            if let Err(err) = self.endpoint.recv(&mut self.recv_buf[..len], &pkt_info) {
                eprintln!("tquic endpoint recv failed: {err:?}");
            }
        }
        Ok(())
    }
}

impl TransportHandler for ClientHandler {
    fn on_conn_created(&mut self, conn: &mut Connection) {
        if let Some(index) = conn.index() {
            self.shared
                .borrow_mut()
                .conns
                .entry(index)
                .or_insert_with(ClientConn::default);
        }
    }

    fn on_conn_established(&mut self, conn: &mut Connection) {
        if let Some(index) = conn.index() {
            if let Some(state) = self.shared.borrow_mut().conns.get_mut(&index) {
                state.ready = true;
            }
        }
    }

    fn on_conn_closed(&mut self, conn: &mut Connection) {
        if let Some(index) = conn.index() {
            let mut shared = self.shared.borrow_mut();
            if let Some(state) = shared.conns.remove(&index) {
                if !state.streams.is_empty() {
                    shared.active_streams = shared
                        .active_streams
                        .saturating_sub(state.streams.len() as u64);
                    set_client_failure(
                        &mut shared,
                        format!("tquic connection {index} closed with active streams"),
                    );
                }
            }
        }
    }

    fn on_stream_created(&mut self, _conn: &mut Connection, _stream_id: u64) {}

    fn on_stream_readable(&mut self, conn: &mut Connection, stream_id: u64) {
        let mut shared = self.shared.borrow_mut();
        client_read_stream(&mut shared, conn, stream_id);
    }

    fn on_stream_writable(&mut self, conn: &mut Connection, stream_id: u64) {
        let mut shared = self.shared.borrow_mut();
        client_write_stream(&mut shared, conn, stream_id);
    }

    fn on_stream_closed(&mut self, _conn: &mut Connection, _stream_id: u64) {}

    fn on_new_token(&mut self, _conn: &mut Connection, _token: Vec<u8>) {}
}

fn client_write_stream(shared: &mut ClientShared, conn: &mut Connection, stream_id: u64) {
    let Some(index) = conn.index() else {
        return;
    };
    let Some(conn_state) = shared.conns.get_mut(&index) else {
        return;
    };
    let Some(stream) = conn_state.streams.get_mut(&stream_id) else {
        return;
    };
    let total = 16 + stream.request_bytes;
    while stream.request_sent < total {
        let remaining = total - stream.request_sent;
        let chunk_len = cmp::min(WRITE_CHUNK_SIZE as u64, remaining) as usize;
        let chunk = build_request_chunk(stream, chunk_len);
        let fin = stream.request_sent + chunk_len as u64 == total;
        match conn.stream_write(stream_id, Bytes::from(chunk), fin) {
            Ok(0) | Err(QuicError::Done) => {
                let _ = conn.stream_want_write(stream_id, true);
                return;
            }
            Ok(written) => {
                stream.request_sent += written as u64;
                if written < chunk_len {
                    let _ = conn.stream_want_write(stream_id, true);
                    return;
                }
            }
            Err(err) => {
                set_client_failure(
                    shared,
                    format!("tquic stream {stream_id} write failed: {err:?}"),
                );
                return;
            }
        }
    }
    let _ = conn.stream_want_write(stream_id, false);
}

fn build_request_chunk(stream: &ClientStream, chunk_len: usize) -> Vec<u8> {
    let mut out = vec![0x5a; chunk_len];
    let base = stream.request_sent;
    for (i, byte) in out.iter_mut().enumerate() {
        let absolute = base + i as u64;
        if absolute < 8 {
            *byte = ((stream.request_bytes >> (56 - absolute * 8)) & 0xff) as u8;
        } else if absolute < 16 {
            let shift = 56 - (absolute - 8) * 8;
            *byte = ((stream.response_bytes >> shift) & 0xff) as u8;
        }
    }
    out
}

fn client_read_stream(shared: &mut ClientShared, conn: &mut Connection, stream_id: u64) {
    let Some(index) = conn.index() else {
        return;
    };
    let mut completed = None;
    let mut failure = None;
    {
        let Some(conn_state) = shared.conns.get_mut(&index) else {
            return;
        };
        let Some(stream) = conn_state.streams.get_mut(&stream_id) else {
            return;
        };
        let mut buf = [0u8; READ_CHUNK_SIZE];
        loop {
            match conn.stream_read(stream_id, &mut buf) {
                Ok((read, fin)) => {
                    stream.response_received += read as u64;
                    if fin {
                        if stream.response_received != stream.response_bytes {
                            failure = Some(format!(
                                "tquic stream {stream_id} received {} bytes, expected {}",
                                stream.response_received, stream.response_bytes
                            ));
                        } else {
                            completed = Some(CompletedStream {
                                conn_index: index,
                                counts: stream.counts,
                                request_bytes: stream.request_bytes,
                                received: stream.response_received,
                                latency: stream.started_at.elapsed(),
                            });
                        }
                        break;
                    }
                    if read == 0 {
                        break;
                    }
                }
                Err(QuicError::Done) => break,
                Err(err) => {
                    failure = Some(format!("tquic stream {stream_id} read failed: {err:?}"));
                    break;
                }
            }
        }
    }
    if let Some(failure) = failure {
        set_client_failure(shared, failure);
    }
    if let Some(done) = completed {
        if let Some(conn_state) = shared.conns.get_mut(&index) {
            conn_state.streams.remove(&stream_id);
        }
        shared.active_streams = shared.active_streams.saturating_sub(1);
        shared.completed.push_back(done);
    }
}

fn set_client_failure(shared: &mut ClientShared, message: String) {
    if shared.failure.is_none() {
        shared.failure = Some(message);
    }
}

impl TransportHandler for ServerHandler {
    fn on_conn_created(&mut self, conn: &mut Connection) {
        if let Some(index) = conn.index() {
            self.conns.entry(index).or_insert_with(ServerConn::default);
        }
    }

    fn on_conn_established(&mut self, conn: &mut Connection) {
        if let Some(index) = conn.index() {
            self.conns.entry(index).or_insert_with(ServerConn::default);
        }
    }

    fn on_conn_closed(&mut self, conn: &mut Connection) {
        if let Some(index) = conn.index() {
            self.conns.remove(&index);
        }
    }

    fn on_stream_created(&mut self, conn: &mut Connection, stream_id: u64) {
        if let Some(index) = conn.index() {
            let conn_state = self.conns.entry(index).or_insert_with(ServerConn::default);
            conn_state
                .streams
                .entry(stream_id)
                .or_insert_with(ServerStream::default);
            let _ = conn.stream_want_read(stream_id, true);
        }
    }

    fn on_stream_readable(&mut self, conn: &mut Connection, stream_id: u64) {
        server_read_stream(&mut self.conns, conn, stream_id);
    }

    fn on_stream_writable(&mut self, conn: &mut Connection, stream_id: u64) {
        server_write_stream(&mut self.conns, conn, stream_id);
    }

    fn on_stream_closed(&mut self, conn: &mut Connection, stream_id: u64) {
        if let Some(index) = conn.index() {
            if let Some(conn_state) = self.conns.get_mut(&index) {
                conn_state.streams.remove(&stream_id);
            }
        }
    }

    fn on_new_token(&mut self, _conn: &mut Connection, _token: Vec<u8>) {}
}

fn server_read_stream(conns: &mut HashMap<u64, ServerConn>, conn: &mut Connection, stream_id: u64) {
    let Some(index) = conn.index() else {
        return;
    };
    let conn_state = conns.entry(index).or_insert_with(ServerConn::default);
    let stream = conn_state
        .streams
        .entry(stream_id)
        .or_insert_with(ServerStream::default);
    let mut buf = [0u8; READ_CHUNK_SIZE];
    loop {
        match conn.stream_read(stream_id, &mut buf) {
            Ok((read, fin)) => {
                let mut offset = 0;
                if stream.header_len < stream.header.len() {
                    let take = cmp::min(stream.header.len() - stream.header_len, read);
                    stream.header[stream.header_len..stream.header_len + take]
                        .copy_from_slice(&buf[..take]);
                    stream.header_len += take;
                    offset += take;
                    if stream.header_len == stream.header.len() {
                        stream.request_bytes =
                            u64::from_be_bytes(stream.header[..8].try_into().unwrap());
                        stream.response_bytes =
                            u64::from_be_bytes(stream.header[8..16].try_into().unwrap());
                    }
                }
                stream.request_received += (read - offset) as u64;
                if fin {
                    if stream.header_len != stream.header.len()
                        || stream.request_received != stream.request_bytes
                    {
                        let _ = conn.close(true, 1, b"bad request");
                        return;
                    }
                    let _ = conn.stream_want_read(stream_id, false);
                    let _ = conn.stream_want_write(stream_id, true);
                    server_write_stream(conns, conn, stream_id);
                    return;
                }
                if read == 0 {
                    break;
                }
            }
            Err(QuicError::Done) => break,
            Err(_) => {
                let _ = conn.close(true, 1, b"read failed");
                break;
            }
        }
    }
}

fn server_write_stream(
    conns: &mut HashMap<u64, ServerConn>,
    conn: &mut Connection,
    stream_id: u64,
) {
    let Some(index) = conn.index() else {
        return;
    };
    let Some(conn_state) = conns.get_mut(&index) else {
        return;
    };
    let Some(stream) = conn_state.streams.get_mut(&stream_id) else {
        return;
    };
    while stream.response_sent < stream.response_bytes {
        let remaining = stream.response_bytes - stream.response_sent;
        let chunk_len = cmp::min(WRITE_CHUNK_SIZE as u64, remaining) as usize;
        let fin = stream.response_sent + chunk_len as u64 == stream.response_bytes;
        let chunk = vec![0x5a; chunk_len];
        match conn.stream_write(stream_id, Bytes::from(chunk), fin) {
            Ok(0) | Err(QuicError::Done) => {
                let _ = conn.stream_want_write(stream_id, true);
                return;
            }
            Ok(written) => {
                stream.response_sent += written as u64;
                if written < chunk_len {
                    let _ = conn.stream_want_write(stream_id, true);
                    return;
                }
                if fin {
                    stream.response_fin = true;
                }
            }
            Err(_) => {
                let _ = conn.close(true, 1, b"write failed");
                return;
            }
        }
    }
    if !stream.response_fin {
        match conn.stream_write(stream_id, Bytes::new(), true) {
            Ok(_) => stream.response_fin = true,
            Err(QuicError::Done) => {
                let _ = conn.stream_want_write(stream_id, true);
                return;
            }
            Err(_) => {
                let _ = conn.close(true, 1, b"finish failed");
                return;
            }
        }
    }
    let _ = conn.stream_want_write(stream_id, false);
}

fn resolve_remote(host: &str, port: u16) -> Result<SocketAddr, AnyError> {
    (host, port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| format!("unable to resolve {host}:{port}").into())
}

fn unspecified_addr(remote: SocketAddr) -> SocketAddr {
    if remote.is_ipv4() {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    } else {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
    }
}

fn cmp_duration(a: Duration, b: Duration) -> Duration {
    if a < b {
        a
    } else {
        b
    }
}

fn new_run_summary(cfg: &Config) -> RunSummary {
    RunSummary {
        schema_version: PROTOCOL_VERSION,
        status: "ok".to_string(),
        mode: cfg.mode.clone(),
        direction: cfg.direction.clone(),
        backend: "tquic".to_string(),
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

fn duration_millis(duration: Duration) -> i64 {
    duration.as_millis() as i64
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
        fs::write(path, summary_json(summary))?;
    }
    Ok(())
}

fn summary_json(summary: &RunSummary) -> String {
    let mut out = String::new();
    out.push_str("{\n");
    push_json_number(
        &mut out,
        "schema_version",
        summary.schema_version as u64,
        true,
    );
    push_json_string(&mut out, "status", &summary.status, true);
    push_json_string(&mut out, "mode", &summary.mode, true);
    push_json_string(&mut out, "direction", &summary.direction, true);
    push_json_string(&mut out, "backend", &summary.backend, true);
    push_json_string(
        &mut out,
        "congestion_control",
        &summary.congestion_control,
        true,
    );
    push_json_string(&mut out, "remote_host", &summary.remote_host, true);
    push_json_number(&mut out, "remote_port", summary.remote_port as u64, true);
    push_json_string(&mut out, "alpn", &summary.alpn, true);
    push_json_i64(&mut out, "elapsed_ms", summary.elapsed_ms, true);
    push_json_i64(&mut out, "warmup_ms", summary.warmup_ms, true);
    push_json_number(&mut out, "bytes_sent", summary.bytes_sent, true);
    push_json_number(&mut out, "bytes_received", summary.bytes_received, true);
    out.push_str("  \"server_counters\": {\n");
    push_json_number(
        &mut out,
        "bytes_sent",
        summary.server_counters.bytes_sent,
        true,
    );
    push_json_number(
        &mut out,
        "bytes_received",
        summary.server_counters.bytes_received,
        true,
    );
    push_json_number(
        &mut out,
        "requests_completed",
        summary.server_counters.requests_completed,
        false,
    );
    out.push_str("  },\n");
    push_json_number(
        &mut out,
        "requests_completed",
        summary.requests_completed,
        true,
    );
    push_json_number(&mut out, "streams", summary.streams, true);
    push_json_number(&mut out, "connections", summary.connections, true);
    push_json_number(
        &mut out,
        "requests_in_flight",
        summary.requests_in_flight,
        true,
    );
    push_json_number(&mut out, "request_bytes", summary.request_bytes, true);
    push_json_number(&mut out, "response_bytes", summary.response_bytes, true);
    push_json_float(
        &mut out,
        "throughput_mib_per_s",
        summary.throughput_mib_per_s,
        true,
    );
    push_json_float(
        &mut out,
        "throughput_gbit_per_s",
        summary.throughput_gbit_per_s,
        true,
    );
    push_json_float(&mut out, "requests_per_s", summary.requests_per_s, true);
    out.push_str("  \"latency\": {\n");
    push_json_number(&mut out, "min_us", summary.latency.min_us, true);
    push_json_number(&mut out, "avg_us", summary.latency.avg_us, true);
    push_json_number(&mut out, "p50_us", summary.latency.p50_us, true);
    push_json_number(&mut out, "p90_us", summary.latency.p90_us, true);
    push_json_number(&mut out, "p99_us", summary.latency.p99_us, true);
    push_json_number(&mut out, "max_us", summary.latency.max_us, false);
    out.push_str("  }");
    if summary.skipped_setup_errors != 0 {
        out.push_str(",\n");
        push_json_number(
            &mut out,
            "skipped_setup_errors",
            summary.skipped_setup_errors,
            false,
        );
    }
    if !summary.failure_reason.is_empty() {
        out.push_str(",\n");
        push_json_string(&mut out, "failure_reason", &summary.failure_reason, false);
    }
    out.push_str("\n}\n");
    out
}

fn push_json_string(out: &mut String, key: &str, value: &str, comma: bool) {
    out.push_str("  \"");
    out.push_str(key);
    out.push_str("\": \"");
    out.push_str(&escape_json(value));
    out.push('"');
    if comma {
        out.push(',');
    }
    out.push('\n');
}

fn push_json_number(out: &mut String, key: &str, value: u64, comma: bool) {
    out.push_str(&format!("  \"{key}\": {value}"));
    if comma {
        out.push(',');
    }
    out.push('\n');
}

fn push_json_i64(out: &mut String, key: &str, value: i64, comma: bool) {
    out.push_str(&format!("  \"{key}\": {value}"));
    if comma {
        out.push(',');
    }
    out.push('\n');
}

fn push_json_float(out: &mut String, key: &str, value: f64, comma: bool) {
    out.push_str(&format!("  \"{key}\": {value:.6}"));
    if comma {
        out.push(',');
    }
    out.push('\n');
}

fn escape_json(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch if ch.is_control() => out.push_str(&format!("\\u{:04x}", ch as u32)),
            ch => out.push(ch),
        }
    }
    out
}

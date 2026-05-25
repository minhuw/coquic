use mio::net::UdpSocket;
use mio::{Events, Interest, Poll, Token};
use quiche::{Connection, ConnectionId};
use ring::rand::{SecureRandom, SystemRandom};
use serde::Serialize;
use std::cmp;
use std::collections::HashMap;
use std::env;
use std::fs;
use std::net::{SocketAddr, ToSocketAddrs};
use std::time::{Duration, Instant};

const APPLICATION_PROTOCOL: &[u8] = b"coquic-perf/1";
const MAX_DATAGRAM_SIZE: usize = 1350;
const TRANSFER_CONNECTION_WINDOW: u64 = 32 * 1024 * 1024;
const TRANSFER_STREAM_WINDOW: u64 = 16 * 1024 * 1024;
const WRITE_CHUNK_SIZE: usize = 32 * 1024;
const READ_CHUNK_SIZE: usize = 64 * 1024;
const DRAIN_TIMEOUT: Duration = Duration::from_secs(2);
const TOKEN: Token = Token(0);

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

#[derive(Default)]
struct Counters {
    bytes_sent: u64,
    bytes_received: u64,
    requests_completed: u64,
    skipped_setup_errors: u64,
    latencies: Vec<Duration>,
}

#[derive(Default)]
struct CompletedStream {
    counts: bool,
    request_bytes: u64,
    received: u64,
    latency: Duration,
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

struct ClientStream {
    send_buf: Vec<u8>,
    sent: usize,
    fin_sent: bool,
    received: u64,
    response_bytes: u64,
    request_bytes: u64,
    counts: bool,
    start: Instant,
}

struct QuicheClient {
    poll: Poll,
    events: Events,
    socket: UdpSocket,
    conn: Connection,
    out: [u8; MAX_DATAGRAM_SIZE],
    buf: [u8; READ_CHUNK_SIZE],
    next_stream_id: u64,
    streams: HashMap<u64, ClientStream>,
}

struct CrrClient {
    client: QuicheClient,
    counts: bool,
    request_opened: bool,
}

struct ServerStream {
    header: [u8; 16],
    header_len: usize,
    request_bytes: u64,
    response_bytes: u64,
    request_received: u64,
    request_fin: bool,
    response_sent: u64,
    response_fin: bool,
}

struct ServerClient {
    conn: Connection,
    streams: HashMap<u64, ServerStream>,
}

fn main() {
    let mut args: Vec<String> = env::args().collect();
    if args.len() < 2 || (args[1] != "client" && args[1] != "server") {
        eprintln!("usage: quiche-perf [client|server] [options]");
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
        if let Err(err) = run_server(&cfg) {
            eprintln!("{err}");
            std::process::exit(1);
        }
        return;
    }

    let mut summary = new_run_summary(&cfg);
    if let Err(err) = run_client(&cfg, &mut summary) {
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

    if ![MODE_BULK, MODE_RR, MODE_CRR].contains(&cfg.mode.as_str()) {
        return Err(format!("unsupported mode: {}", cfg.mode).into());
    }
    if cfg.io_backend != "socket" && cfg.io_backend != "io_uring" {
        return Err(format!("unsupported io-backend label: {}", cfg.io_backend).into());
    }
    if cfg.io_backend != "socket" {
        return Err("quiche-perf only supports the socket backend".into());
    }
    if !["default", "cubic", "bbr", "newreno", "copa"].contains(&cfg.congestion_control.as_str()) {
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

fn new_quiche_config(cfg: &Config, server: bool) -> Result<quiche::Config, AnyError> {
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
    if server {
        config.load_cert_chain_from_pem_file(&cfg.certificate_chain)?;
        config.load_priv_key_from_pem_file(&cfg.private_key)?;
    } else {
        config.verify_peer(cfg.verify_peer);
        if !cfg.verify_peer {
            config.verify_peer(false);
        }
    }
    config.set_application_protos(&[APPLICATION_PROTOCOL])?;
    config.set_max_idle_timeout(30_000);
    config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_initial_max_data(TRANSFER_CONNECTION_WINDOW);
    config.set_initial_max_stream_data_bidi_local(TRANSFER_STREAM_WINDOW);
    config.set_initial_max_stream_data_bidi_remote(TRANSFER_STREAM_WINDOW);
    config.set_initial_max_stream_data_uni(TRANSFER_STREAM_WINDOW);
    config.set_initial_max_streams_bidi(4096);
    config.set_initial_max_streams_uni(0);
    config.set_disable_active_migration(true);
    match cfg.congestion_control.as_str() {
        "default" | "cubic" => {}
        "newreno" => config.set_cc_algorithm_name("reno")?,
        "copa" => return Err("quiche-perf does not provide Copa; use PERF_CONGESTION_CONTROLS=default for paired quiche baselines".into()),
        "bbr" => config.set_cc_algorithm_name("bbr")?,
        other => return Err(format!("quiche-perf unsupported congestion-control label: {other}").into()),
    }
    Ok(config)
}

fn run_server(cfg: &Config) -> Result<(), AnyError> {
    let addr: SocketAddr = format!("{}:{}", cfg.host, cfg.port).parse()?;
    let mut socket = UdpSocket::bind(addr)?;
    let mut poll = Poll::new()?;
    poll.registry()
        .register(&mut socket, TOKEN, Interest::READABLE)?;
    let mut events = Events::with_capacity(1024);
    let mut config = new_quiche_config(cfg, true)?;
    let rng = SystemRandom::new();
    let mut clients: HashMap<ConnectionId<'static>, ServerClient> = HashMap::new();
    let local_addr = socket.local_addr()?;
    let mut buf = [0_u8; 65535];
    let mut out = [0_u8; MAX_DATAGRAM_SIZE];

    loop {
        let timeout = clients.values().filter_map(|c| c.conn.timeout()).min();
        poll.poll(&mut events, timeout)?;
        if events.is_empty() {
            for client in clients.values_mut() {
                client.conn.on_timeout();
            }
        }

        'read: loop {
            let (len, from) = match socket.recv_from(&mut buf) {
                Ok(v) => v,
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => break 'read,
                Err(err) => return Err(err.into()),
            };
            let pkt = &mut buf[..len];
            let hdr = match quiche::Header::from_slice(pkt, quiche::MAX_CONN_ID_LEN) {
                Ok(v) => v,
                Err(_) => continue,
            };

            let client = if !clients.contains_key(&hdr.dcid) {
                if hdr.ty != quiche::Type::Initial {
                    continue;
                }
                if !quiche::version_is_supported(hdr.version) {
                    let len = quiche::negotiate_version(&hdr.scid, &hdr.dcid, &mut out)?;
                    let _ = socket.send_to(&out[..len], from);
                    continue;
                }
                let mut scid = [0_u8; quiche::MAX_CONN_ID_LEN];
                rng.fill(&mut scid).map_err(|_| "rng failed")?;
                let scid = ConnectionId::from_vec(scid.to_vec());
                let conn = quiche::accept(&scid, None, local_addr, from, &mut config)?;
                clients.insert(
                    scid.clone(),
                    ServerClient {
                        conn,
                        streams: HashMap::new(),
                    },
                );
                clients.get_mut(&scid).unwrap()
            } else {
                let Some(client) = clients.get_mut(&hdr.dcid) else {
                    continue;
                };
                client
            };
            let recv_info = quiche::RecvInfo {
                to: local_addr,
                from,
            };
            if client.conn.recv(pkt, recv_info).is_err() {
                continue;
            }
            handle_server_client(client)?;
        }

        for client in clients.values_mut() {
            handle_server_client(client)?;
            flush_server_packets(&socket, client, &mut out)?;
        }
        clients.retain(|_, client| !client.conn.is_closed());
    }
}

fn handle_server_client(client: &mut ServerClient) -> Result<(), AnyError> {
    let mut buf = [0_u8; READ_CHUNK_SIZE];
    let readable: Vec<u64> = client.conn.readable().collect();
    for stream_id in readable {
        loop {
            match client.conn.stream_recv(stream_id, &mut buf) {
                Ok((read, fin)) => {
                    let state = client
                        .streams
                        .entry(stream_id)
                        .or_insert_with(ServerStream::new);
                    state.receive(&buf[..read], fin)?;
                }
                Err(quiche::Error::Done) => break,
                Err(err) => return Err(err.into()),
            }
        }
    }

    let writable: Vec<u64> = client.conn.writable().collect();
    for stream_id in writable {
        if let Some(state) = client.streams.get_mut(&stream_id) {
            state.write_response(&mut client.conn, stream_id)?;
        }
    }
    let ready: Vec<u64> = client
        .streams
        .iter()
        .filter_map(|(id, state)| (state.request_fin && !state.response_fin).then_some(*id))
        .collect();
    for stream_id in ready {
        if let Some(state) = client.streams.get_mut(&stream_id) {
            state.write_response(&mut client.conn, stream_id)?;
        }
    }
    client
        .streams
        .retain(|_, state| !(state.request_fin && state.response_fin));
    Ok(())
}

impl ServerStream {
    fn new() -> Self {
        Self {
            header: [0; 16],
            header_len: 0,
            request_bytes: 0,
            response_bytes: 0,
            request_received: 0,
            request_fin: false,
            response_sent: 0,
            response_fin: false,
        }
    }

    fn receive(&mut self, mut bytes: &[u8], fin: bool) -> Result<(), AnyError> {
        if self.header_len < self.header.len() {
            let take = cmp::min(self.header.len() - self.header_len, bytes.len());
            self.header[self.header_len..self.header_len + take].copy_from_slice(&bytes[..take]);
            self.header_len += take;
            bytes = &bytes[take..];
            if self.header_len == self.header.len() {
                self.request_bytes = u64::from_be_bytes(self.header[0..8].try_into().unwrap());
                self.response_bytes = u64::from_be_bytes(self.header[8..16].try_into().unwrap());
            }
        }
        self.request_received += bytes.len() as u64;
        if fin {
            if self.header_len != self.header.len() {
                return Err("quiche-perf malformed stream request header".into());
            }
            self.request_fin = true;
        }
        Ok(())
    }

    fn write_response(&mut self, conn: &mut Connection, stream_id: u64) -> Result<(), AnyError> {
        if !self.request_fin || self.response_fin {
            return Ok(());
        }
        let data = [0x5a_u8; WRITE_CHUNK_SIZE];
        loop {
            let remaining = self.response_bytes.saturating_sub(self.response_sent);
            let chunk = cmp::min(remaining, data.len() as u64) as usize;
            let fin = chunk as u64 == remaining;
            match conn.stream_send(stream_id, &data[..chunk], fin) {
                Ok(written) => {
                    self.response_sent += written as u64;
                    if fin && written == chunk {
                        self.response_fin = true;
                        break;
                    }
                    if written == 0 {
                        break;
                    }
                }
                Err(quiche::Error::Done) => break,
                Err(err) => return Err(err.into()),
            }
        }
        Ok(())
    }
}

fn flush_server_packets(
    socket: &UdpSocket,
    client: &mut ServerClient,
    out: &mut [u8; MAX_DATAGRAM_SIZE],
) -> Result<(), AnyError> {
    loop {
        match client.conn.send(out) {
            Ok((write, send_info)) => match socket.send_to(&out[..write], send_info.to) {
                Ok(_) => {}
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(err) => return Err(err.into()),
            },
            Err(quiche::Error::Done) => break,
            Err(err) => return Err(err.into()),
        }
    }
    Ok(())
}

fn run_client(cfg: &Config, summary: &mut RunSummary) -> Result<(), AnyError> {
    let run_start = Instant::now();
    let mut counters = Counters::default();
    let elapsed = match cfg.mode.as_str() {
        MODE_BULK => {
            if cfg.direction == DIRECTION_DOWNLOAD && !cfg.total_bytes.set {
                run_timed_bulk_download(cfg, &mut counters)?;
                cfg.duration
            } else {
                run_fixed_bulk(cfg, &mut counters)?;
                run_start.elapsed()
            }
        }
        MODE_RR => {
            run_rr(cfg, &mut counters)?;
            if cfg.requests.set {
                run_start.elapsed()
            } else {
                cfg.duration
            }
        }
        MODE_CRR => {
            run_crr(cfg, &mut counters)?;
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
    Ok(())
}

fn run_timed_bulk_download(cfg: &Config, counters: &mut Counters) -> Result<(), AnyError> {
    let mut client = QuicheClient::connect(cfg)?;
    let measure_start = Instant::now() + cfg.warmup;
    let measure_deadline = measure_start + cfg.duration;
    for _ in 0..cfg.streams {
        client.open_request(false, 0, cfg.response_bytes)?;
    }
    while Instant::now() < measure_deadline {
        for completed in client.drive(Some(measure_deadline))? {
            if completed.counts && Instant::now() >= measure_start {
                counters.bytes_received += completed.received;
            }
        }
        while client.streams.len() < int_cap(cfg.streams) && Instant::now() < measure_deadline {
            client.open_request(Instant::now() >= measure_start, 0, cfg.response_bytes)?;
        }
    }
    client.drain(DRAIN_TIMEOUT)?;
    Ok(())
}

fn run_fixed_bulk(cfg: &Config, counters: &mut Counters) -> Result<(), AnyError> {
    if !cfg.total_bytes.set {
        return Err("fixed bulk requires --total-bytes for quiche client".into());
    }
    let mut client = QuicheClient::connect(cfg)?;
    let per_stream = cfg.total_bytes.value / cfg.streams;
    let remainder = cfg.total_bytes.value % cfg.streams;
    for i in 0..cfg.streams {
        let target = per_stream + u64::from(i < remainder);
        if cfg.direction == DIRECTION_UPLOAD {
            client.open_request(true, target, 0)?;
        } else {
            client.open_request(true, 0, target)?;
        }
    }
    while !client.streams.is_empty() {
        for completed in client.drive(None)? {
            counters.bytes_sent += completed.request_bytes;
            counters.bytes_received += completed.received;
        }
    }
    Ok(())
}

fn run_rr(cfg: &Config, counters: &mut Counters) -> Result<(), AnyError> {
    let mut client = QuicheClient::connect(cfg)?;
    let measure_start = Instant::now() + cfg.warmup;
    let measure_deadline = measure_start + cfg.duration;
    let mut started = 0_u64;
    while client.streams.len() < int_cap(cfg.requests_in_flight) {
        client.open_request(
            cfg.requests.set || Instant::now() >= measure_start,
            cfg.request_bytes,
            cfg.response_bytes,
        )?;
        started += 1;
    }
    loop {
        if !cfg.requests.set && Instant::now() >= measure_deadline {
            break;
        }
        if cfg.requests.set && started >= cfg.requests.value && client.streams.is_empty() {
            break;
        }
        for completed in client.drive(Some(measure_deadline))? {
            if completed.counts && Instant::now() >= measure_start {
                counters.bytes_sent += completed.request_bytes;
                counters.bytes_received += completed.received;
                counters.requests_completed += 1;
                counters.latencies.push(completed.latency);
            }
        }
        while client.streams.len() < int_cap(cfg.requests_in_flight) {
            if cfg.requests.set && started >= cfg.requests.value {
                break;
            }
            if !cfg.requests.set && Instant::now() >= measure_deadline {
                break;
            }
            client.open_request(
                cfg.requests.set || Instant::now() >= measure_start,
                cfg.request_bytes,
                cfg.response_bytes,
            )?;
            started += 1;
        }
    }
    client.drain(DRAIN_TIMEOUT)?;
    Ok(())
}

fn run_crr(cfg: &Config, counters: &mut Counters) -> Result<(), AnyError> {
    let measure_start = Instant::now() + cfg.warmup;
    let measure_deadline = measure_start + cfg.duration;
    let connect_deadline = measure_deadline + DRAIN_TIMEOUT;
    let mut started = 0_u64;
    let mut clients: Vec<CrrClient> = Vec::with_capacity(int_cap(cfg.connections));
    fill_crr_clients(
        cfg,
        counters,
        measure_start,
        measure_deadline,
        connect_deadline,
        &mut started,
        &mut clients,
    )?;

    while (cfg.requests.set && started < cfg.requests.value)
        || !clients.is_empty()
        || (!cfg.requests.set && Instant::now() < measure_deadline)
    {
        let mut index = 0;
        let mut made_progress = false;
        while index < clients.len() {
            let poll_deadline = Instant::now();
            let completed = clients[index].client.drive(Some(poll_deadline))?;
            if !completed.is_empty() {
                made_progress = true;
            }

            if clients[index].client.conn.is_closed() && !clients[index].request_opened {
                if cfg.requests.set {
                    return Err("quiche connection closed during CRR setup".into());
                }
                counters.skipped_setup_errors += 1;
                clients.swap_remove(index);
                continue;
            }

            if !clients[index].client.conn.is_established()
                && !clients[index].request_opened
                && Instant::now() >= connect_deadline
            {
                if cfg.requests.set {
                    return Err("quiche CRR connection setup timed out".into());
                }
                counters.skipped_setup_errors += 1;
                clients.swap_remove(index);
                continue;
            }

            if clients[index].client.conn.is_established() && !clients[index].request_opened {
                let counts = clients[index].counts;
                clients[index].client.open_request(
                    counts,
                    cfg.request_bytes,
                    cfg.response_bytes,
                )?;
                clients[index].request_opened = true;
                made_progress = true;
            }

            let mut completed_this_client = false;
            for completed in completed {
                if completed.counts && Instant::now() >= measure_start {
                    counters.bytes_sent += completed.request_bytes;
                    counters.bytes_received += completed.received;
                    counters.requests_completed += 1;
                    counters.latencies.push(completed.latency);
                }
                completed_this_client = true;
            }
            if completed_this_client && clients[index].client.streams.is_empty() {
                clients.swap_remove(index);
            } else {
                index += 1;
            }
        }

        fill_crr_clients(
            cfg,
            counters,
            measure_start,
            measure_deadline,
            connect_deadline,
            &mut started,
            &mut clients,
        )?;

        if clients.is_empty() {
            if cfg.requests.set && started >= cfg.requests.value {
                break;
            }
            if !cfg.requests.set && Instant::now() >= measure_deadline {
                break;
            }
        }
        if !made_progress {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    Ok(())
}

fn fill_crr_clients(
    cfg: &Config,
    counters: &mut Counters,
    measure_start: Instant,
    measure_deadline: Instant,
    connect_deadline: Instant,
    started: &mut u64,
    clients: &mut Vec<CrrClient>,
) -> Result<(), AnyError> {
    while clients.len() < int_cap(cfg.connections) {
        if cfg.requests.set && *started >= cfg.requests.value {
            break;
        }
        if !cfg.requests.set && Instant::now() >= measure_deadline {
            break;
        }
        match open_crr_client(cfg, measure_start, connect_deadline) {
            Ok(client) => {
                clients.push(client);
                *started += 1;
            }
            Err(err) if !cfg.requests.set => {
                counters.skipped_setup_errors += 1;
                std::thread::sleep(Duration::from_millis(2));
                if Instant::now() >= measure_deadline {
                    break;
                }
                eprintln!("quiche crr setup skipped: {err}");
            }
            Err(err) => return Err(err),
        }
    }
    Ok(())
}

fn open_crr_client(
    cfg: &Config,
    measure_start: Instant,
    _connect_deadline: Instant,
) -> Result<CrrClient, AnyError> {
    let client = QuicheClient::start_connecting(cfg)?;
    let counts = cfg.requests.set || Instant::now() >= measure_start;
    Ok(CrrClient {
        client,
        counts,
        request_opened: false,
    })
}

impl QuicheClient {
    fn connect(cfg: &Config) -> Result<Self, AnyError> {
        let deadline = Instant::now() + Duration::from_secs(10);
        Self::connect_until(cfg, deadline)
    }

    fn connect_until(cfg: &Config, deadline: Instant) -> Result<Self, AnyError> {
        let mut client = Self::start_connecting(cfg)?;
        while !client.conn.is_established() {
            client.drive(Some(deadline))?;
            if client.conn.is_closed() {
                return Err("quiche connection closed during handshake".into());
            }
            if Instant::now() >= deadline {
                return Err("quiche handshake timed out".into());
            }
        }
        Ok(client)
    }

    fn start_connecting(cfg: &Config) -> Result<Self, AnyError> {
        let peer_addr = resolve_remote(&cfg.host, cfg.port)?;
        let std_socket = std::net::UdpSocket::bind("0.0.0.0:0")?;
        std_socket.set_nonblocking(true)?;
        let mut socket = UdpSocket::from_std(std_socket);
        let poll = Poll::new()?;
        poll.registry()
            .register(&mut socket, TOKEN, Interest::READABLE)?;
        let local_addr = socket.local_addr()?;
        let mut config = new_quiche_config(cfg, false)?;
        let mut scid = [0_u8; quiche::MAX_CONN_ID_LEN];
        SystemRandom::new()
            .fill(&mut scid)
            .map_err(|_| "rng failed")?;
        let scid = ConnectionId::from_ref(&scid);
        let conn = quiche::connect(
            Some(&cfg.server_name),
            &scid,
            local_addr,
            peer_addr,
            &mut config,
        )?;
        let mut client = Self {
            poll,
            events: Events::with_capacity(1024),
            socket,
            conn,
            out: [0; MAX_DATAGRAM_SIZE],
            buf: [0; READ_CHUNK_SIZE],
            next_stream_id: 0,
            streams: HashMap::new(),
        };
        client.flush()?;
        Ok(client)
    }

    fn open_request(
        &mut self,
        counts: bool,
        request_bytes: u64,
        response_bytes: u64,
    ) -> Result<(), AnyError> {
        let stream_id = self.next_stream_id;
        self.next_stream_id += 4;
        let mut send_buf = Vec::with_capacity(16 + int_cap(request_bytes));
        send_buf.extend_from_slice(&request_bytes.to_be_bytes());
        send_buf.extend_from_slice(&response_bytes.to_be_bytes());
        send_buf.resize(send_buf.len() + int_cap(request_bytes), 0x5a);
        self.streams.insert(
            stream_id,
            ClientStream {
                send_buf,
                sent: 0,
                fin_sent: false,
                received: 0,
                response_bytes,
                request_bytes,
                counts,
                start: Instant::now(),
            },
        );
        self.try_send_stream(stream_id)?;
        self.flush()?;
        Ok(())
    }

    fn drive(&mut self, deadline: Option<Instant>) -> Result<Vec<CompletedStream>, AnyError> {
        let now = Instant::now();
        let quic_timeout = self.conn.timeout();
        let deadline_timeout = deadline.map(|deadline| deadline.saturating_duration_since(now));
        let timeout = match (quic_timeout, deadline_timeout) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        };
        let timeout_is_quic = match (quic_timeout, deadline_timeout) {
            (Some(a), Some(b)) => a <= b,
            (Some(_), None) => true,
            _ => false,
        };
        self.poll.poll(&mut self.events, timeout)?;
        if self.events.is_empty() && timeout_is_quic {
            self.conn.on_timeout();
        }

        'read: loop {
            let (len, from) = match self.socket.recv_from(&mut self.buf) {
                Ok(v) => v,
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => break 'read,
                Err(err) => return Err(err.into()),
            };
            let recv_info = quiche::RecvInfo {
                to: self.socket.local_addr()?,
                from,
            };
            let _ = self.conn.recv(&mut self.buf[..len], recv_info);
        }

        let writable: Vec<u64> = self.conn.writable().collect();
        for stream_id in writable {
            self.try_send_stream(stream_id)?;
        }

        let mut completed = Vec::new();
        let readable: Vec<u64> = self.conn.readable().collect();
        for stream_id in readable {
            while let Ok((read, fin)) = self
                .conn
                .stream_recv(stream_id, &mut self.buf[..READ_CHUNK_SIZE])
            {
                if let Some(state) = self.streams.get_mut(&stream_id) {
                    state.received += read as u64;
                    if fin {
                        if state.received != state.response_bytes {
                            return Err(format!(
                                "stream {stream_id} received {} bytes, expected {}",
                                state.received, state.response_bytes
                            )
                            .into());
                        }
                        let state = self.streams.remove(&stream_id).unwrap();
                        completed.push(CompletedStream {
                            counts: state.counts,
                            request_bytes: state.request_bytes,
                            received: state.received,
                            latency: state.start.elapsed(),
                        });
                        break;
                    }
                }
            }
        }
        self.flush()?;
        Ok(completed)
    }

    fn drain(&mut self, duration: Duration) -> Result<(), AnyError> {
        let deadline = Instant::now() + duration;
        while !self.streams.is_empty() && Instant::now() < deadline {
            let _ = self.drive(Some(deadline))?;
        }
        Ok(())
    }

    fn try_send_stream(&mut self, stream_id: u64) -> Result<(), AnyError> {
        let Some(state) = self.streams.get_mut(&stream_id) else {
            return Ok(());
        };
        while !state.fin_sent {
            let remaining = &state.send_buf[state.sent..];
            let chunk = cmp::min(remaining.len(), WRITE_CHUNK_SIZE);
            let fin = state.sent + chunk == state.send_buf.len();
            match self.conn.stream_send(stream_id, &remaining[..chunk], fin) {
                Ok(written) => {
                    state.sent += written;
                    if fin && written == chunk {
                        state.fin_sent = true;
                        break;
                    }
                    if written == 0 {
                        break;
                    }
                }
                Err(quiche::Error::Done) => break,
                Err(err) => return Err(err.into()),
            }
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<(), AnyError> {
        loop {
            match self.conn.send(&mut self.out) {
                Ok((write, send_info)) => {
                    match self.socket.send_to(&self.out[..write], send_info.to) {
                        Ok(_) => {}
                        Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => break,
                        Err(err) => return Err(err.into()),
                    }
                }
                Err(quiche::Error::Done) => break,
                Err(err) => return Err(err.into()),
            }
        }
        Ok(())
    }
}

fn resolve_remote(host: &str, port: u16) -> Result<SocketAddr, AnyError> {
    (host, port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| format!("unable to resolve {host}:{port}").into())
}

fn new_run_summary(cfg: &Config) -> RunSummary {
    RunSummary {
        schema_version: 1,
        status: "ok".to_string(),
        mode: cfg.mode.clone(),
        direction: cfg.direction.clone(),
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
    let mut micros: Vec<u64> = samples.iter().map(|s| s.as_micros() as u64).collect();
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

fn duration_millis(duration: Duration) -> i64 {
    duration.as_millis().try_into().unwrap_or(i64::MAX)
}

fn int_cap(value: u64) -> usize {
    value.min(usize::MAX as u64) as usize
}

fn is_zero(value: &u64) -> bool {
    *value == 0
}

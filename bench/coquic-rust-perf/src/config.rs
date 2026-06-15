use crate::{PerfError, Result};
use coquic::{CongestionControl, Role as QuicRole, TlsIdentity};
use std::cmp;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub const APPLICATION_PROTOCOL: &[u8] = b"coquic-perf/1";
pub const PERF_MAX_OUTBOUND_DATAGRAM_SIZE: usize = 1472;
pub const PERF_PMTUD_MAX_DATAGRAM_SIZE: usize = 0;
pub const PERF_MIN_UDP_PAYLOAD_SIZE: usize = 1200;
pub const PERF_TRANSFER_CONNECTION_RECEIVE_WINDOW: u64 = 32 * 1024 * 1024;
pub const PERF_TRANSFER_STREAM_RECEIVE_WINDOW: u64 = 16 * 1024 * 1024;
pub const PERF_ACK_ELICITING_THRESHOLD: u64 = 2;
pub const PERF_COPA_BULK_ACK_ELICITING_THRESHOLD: u64 = 1;
pub const PERF_COPA_INTERACTIVE_ACK_ELICITING_THRESHOLD: u64 = 8;
pub const PERF_SERVER_INITIAL_MAX_BIDIRECTIONAL_STREAMS: u64 = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Role {
    Server,
    Client,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Bulk,
    Rr,
    Crr,
    #[serde(rename = "persistent-rr")]
    PersistentRr,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    Upload,
    Download,
}

#[derive(Clone, Debug)]
pub struct PerfConfig {
    pub role: Role,
    pub mode: Mode,
    pub direction: Direction,
    pub host: String,
    pub port: u16,
    pub server_name: String,
    pub verify_peer: bool,
    pub certificate_chain_path: PathBuf,
    pub private_key_path: PathBuf,
    pub json_out: Option<PathBuf>,
    pub request_bytes: usize,
    pub response_bytes: usize,
    pub streams: usize,
    pub connections: usize,
    pub requests_in_flight: usize,
    pub requests: Option<usize>,
    pub total_bytes: Option<usize>,
    pub max_outbound_datagram_size: usize,
    pub pmtud_max_datagram_size: usize,
    pub warmup: Duration,
    pub duration: Duration,
    pub congestion_control: CongestionControl,
}

impl Default for PerfConfig {
    fn default() -> Self {
        Self {
            role: Role::Server,
            mode: Mode::Bulk,
            direction: Direction::Download,
            host: "127.0.0.1".to_owned(),
            port: 4433,
            server_name: "localhost".to_owned(),
            verify_peer: false,
            certificate_chain_path: PathBuf::from("tests/fixtures/quic-server-cert.pem"),
            private_key_path: PathBuf::from("tests/fixtures/quic-server-key.pem"),
            json_out: None,
            request_bytes: 64,
            response_bytes: 64,
            streams: 1,
            connections: 1,
            requests_in_flight: 1,
            requests: None,
            total_bytes: None,
            max_outbound_datagram_size: PERF_MAX_OUTBOUND_DATAGRAM_SIZE,
            pmtud_max_datagram_size: PERF_PMTUD_MAX_DATAGRAM_SIZE,
            warmup: Duration::ZERO,
            duration: Duration::from_secs(5),
            congestion_control: CongestionControl::NewReno,
        }
    }
}

pub fn parse_runtime_args(args: impl IntoIterator<Item = String>) -> Result<PerfConfig> {
    let mut args: Vec<String> = args.into_iter().collect();
    if args.is_empty() {
        return Err(PerfError::new(usage()));
    }

    let role = args.remove(0);
    let mut config = PerfConfig::default();
    config.role = match role.as_str() {
        "server" => Role::Server,
        "client" => Role::Client,
        _ => return Err(PerfError::new(usage())),
    };

    let mut saw_direction = false;
    let mut index = 0;
    while index < args.len() {
        let arg = args[index].as_str();
        index += 1;

        if arg == "--verify-peer" {
            config.verify_peer = true;
            continue;
        }

        let value = require_value(&args, &mut index, arg)?;
        match arg {
            "--host" => config.host = value.to_owned(),
            "--port" => {
                let port = parse_size(value)?;
                if port > u16::MAX as usize {
                    return Err(PerfError::new(usage()));
                }
                config.port = port as u16;
            }
            "--io-backend" => {
                if value != "socket" {
                    return Err(PerfError::new(
                        "coquic-rust-perf currently supports --io-backend socket",
                    ));
                }
            }
            "--congestion-control" => config.congestion_control = parse_congestion_control(value)?,
            "--mode" => config.mode = parse_mode(value)?,
            "--direction" => {
                saw_direction = true;
                config.direction = parse_direction(value)?;
            }
            "--request-bytes" => config.request_bytes = parse_size(value)?,
            "--response-bytes" => config.response_bytes = parse_size(value)?,
            "--streams" => config.streams = parse_size(value)?,
            "--connections" => config.connections = parse_size(value)?,
            "--requests-in-flight" => config.requests_in_flight = parse_size(value)?,
            "--requests" => config.requests = Some(parse_size(value)?),
            "--total-bytes" => config.total_bytes = Some(parse_size(value)?),
            "--max-outbound-datagram-size" => {
                config.max_outbound_datagram_size = parse_size(value)?;
                if config.max_outbound_datagram_size < PERF_MIN_UDP_PAYLOAD_SIZE {
                    return Err(PerfError::new(usage()));
                }
            }
            "--pmtud-max-datagram-size" => {
                config.pmtud_max_datagram_size = parse_size(value)?;
                if config.pmtud_max_datagram_size != 0
                    && config.pmtud_max_datagram_size < PERF_MIN_UDP_PAYLOAD_SIZE
                {
                    return Err(PerfError::new(usage()));
                }
            }
            "--warmup" => config.warmup = parse_duration(value)?,
            "--duration" => config.duration = parse_duration(value)?,
            "--certificate-chain" => config.certificate_chain_path = PathBuf::from(value),
            "--private-key" => config.private_key_path = PathBuf::from(value),
            "--server-name" => config.server_name = value.to_owned(),
            "--json-out" => config.json_out = Some(PathBuf::from(value)),
            _ => return Err(PerfError::new(usage())),
        }
    }

    if config.mode != Mode::Bulk && saw_direction {
        return Err(PerfError::new(usage()));
    }
    if config.streams == 0 || config.connections == 0 || config.requests_in_flight == 0 {
        return Err(PerfError::new(usage()));
    }
    if config.mode == Mode::PersistentRr
        && (config.request_bytes == 0 || config.response_bytes == 0)
    {
        return Err(PerfError::new(usage()));
    }

    Ok(config)
}

pub fn client_endpoint_config(config: &PerfConfig) -> coquic::quic::EndpointConfig {
    let mut endpoint = coquic::quic::EndpointConfig::default();
    endpoint.core.role = QuicRole::Client;
    endpoint.core.verify_peer = config.verify_peer;
    endpoint.core.application_protocol = APPLICATION_PROTOCOL.to_vec();
    endpoint.core.max_outbound_datagram_size = config.max_outbound_datagram_size;
    endpoint.core.emit_shared_receive_stream_data = true;
    apply_transport_defaults(config, &mut endpoint.core.transport);
    endpoint
}

pub fn server_endpoint_config(config: &PerfConfig) -> Result<coquic::quic::EndpointConfig> {
    let mut endpoint = coquic::quic::EndpointConfig::default();
    endpoint.core.role = QuicRole::Server;
    endpoint.core.verify_peer = config.verify_peer;
    endpoint.core.application_protocol = APPLICATION_PROTOCOL.to_vec();
    endpoint.core.identity = Some(TlsIdentity {
        certificate_pem: read_file(&config.certificate_chain_path)?,
        private_key_pem: read_file(&config.private_key_path)?,
    });
    endpoint.core.max_outbound_datagram_size = config.max_outbound_datagram_size;
    endpoint.core.emit_shared_receive_stream_data = true;
    apply_transport_defaults(config, &mut endpoint.core.transport);
    endpoint.core.transport.initial_max_streams_bidi = cmp::max(
        endpoint.core.transport.initial_max_streams_bidi,
        PERF_SERVER_INITIAL_MAX_BIDIRECTIONAL_STREAMS,
    );
    Ok(endpoint)
}

fn apply_transport_defaults(config: &PerfConfig, transport: &mut coquic::TransportConfig) {
    transport.congestion_control = config.congestion_control;
    transport.enable_hystart_plus_plus = perf_enable_hystart_plus_plus(config);
    transport.send_stream_fairness = perf_send_stream_fairness(config);
    transport.ack_eliciting_threshold = perf_ack_eliciting_threshold(config);
    transport.pmtud_max_datagram_size = config.pmtud_max_datagram_size;
    transport.initial_max_data = PERF_TRANSFER_CONNECTION_RECEIVE_WINDOW;
    transport.initial_max_stream_data_bidi_local = PERF_TRANSFER_STREAM_RECEIVE_WINDOW;
    transport.initial_max_stream_data_bidi_remote = PERF_TRANSFER_STREAM_RECEIVE_WINDOW;
}

fn perf_ack_eliciting_threshold(config: &PerfConfig) -> u64 {
    if config.congestion_control == CongestionControl::Copa {
        if config.mode == Mode::Bulk {
            PERF_COPA_BULK_ACK_ELICITING_THRESHOLD
        } else {
            PERF_COPA_INTERACTIVE_ACK_ELICITING_THRESHOLD
        }
    } else {
        PERF_ACK_ELICITING_THRESHOLD
    }
}

fn perf_enable_hystart_plus_plus(config: &PerfConfig) -> bool {
    if config.mode != Mode::Bulk {
        return true;
    }
    config.congestion_control != CongestionControl::NewReno
        && config.congestion_control != CongestionControl::Cubic
}

fn perf_send_stream_fairness(config: &PerfConfig) -> bool {
    config.mode != Mode::Bulk
}

fn read_file(path: &Path) -> Result<Vec<u8>> {
    fs::read(path)
        .map_err(|error| PerfError::new(format!("failed to read {}: {error}", path.display())))
}

fn require_value<'a>(args: &'a [String], index: &mut usize, arg: &str) -> Result<&'a str> {
    if *index >= args.len() {
        return Err(PerfError::new(format!(
            "missing value for {arg}\n{}",
            usage()
        )));
    }
    let value = args[*index].as_str();
    *index += 1;
    Ok(value)
}

fn parse_size(value: &str) -> Result<usize> {
    value.parse::<usize>().map_err(Into::into)
}

fn parse_duration(value: &str) -> Result<Duration> {
    if let Some(ms) = value.strip_suffix("ms") {
        return Ok(Duration::from_millis(ms.parse()?));
    }
    if let Some(seconds) = value.strip_suffix('s') {
        return Ok(Duration::from_secs(seconds.parse()?));
    }
    Err(PerfError::new("duration must use ms or s suffix"))
}

fn parse_mode(value: &str) -> Result<Mode> {
    match value {
        "bulk" => Ok(Mode::Bulk),
        "rr" => Ok(Mode::Rr),
        "crr" => Ok(Mode::Crr),
        "persistent-rr" => Ok(Mode::PersistentRr),
        _ => Err(PerfError::new(usage())),
    }
}

fn parse_direction(value: &str) -> Result<Direction> {
    match value {
        "upload" => Ok(Direction::Upload),
        "download" => Ok(Direction::Download),
        _ => Err(PerfError::new(usage())),
    }
}

fn parse_congestion_control(value: &str) -> Result<CongestionControl> {
    match value {
        "newreno" => Ok(CongestionControl::NewReno),
        "cubic" => Ok(CongestionControl::Cubic),
        "bbr" => Ok(CongestionControl::Bbr),
        "copa" => Ok(CongestionControl::Copa),
        "pcc" => Ok(CongestionControl::Pcc),
        "pcc-vivace" | "pcc_vivace" => Ok(CongestionControl::PccVivace),
        _ => Err(PerfError::new(usage())),
    }
}

pub fn mode_name(mode: Mode) -> &'static str {
    match mode {
        Mode::Bulk => "bulk",
        Mode::Rr => "rr",
        Mode::Crr => "crr",
        Mode::PersistentRr => "persistent-rr",
    }
}

pub fn direction_name(direction: Direction) -> &'static str {
    match direction {
        Direction::Upload => "upload",
        Direction::Download => "download",
    }
}

pub fn congestion_control_name(congestion_control: CongestionControl) -> &'static str {
    match congestion_control {
        CongestionControl::NewReno => "newreno",
        CongestionControl::Cubic => "cubic",
        CongestionControl::Bbr => "bbr",
        CongestionControl::Copa => "copa",
        CongestionControl::Pcc => "pcc",
        CongestionControl::PccVivace => "pcc-vivace",
    }
}

fn usage() -> &'static str {
    "usage: coquic-rust-perf [server|client] [--host HOST] [--port PORT] \
     [--io-backend socket] [--congestion-control newreno|cubic|bbr|copa|pcc|pcc-vivace] \
     [--mode bulk|rr|crr|persistent-rr] [--direction upload|download] [--request-bytes N] \
     [--response-bytes N] [--streams N] [--connections N] \
     [--requests-in-flight N] [--requests N] [--total-bytes N] \
     [--warmup 250ms|2s] [--duration 250ms|2s] \
     [--max-outbound-datagram-size N] [--pmtud-max-datagram-size N] \
     [--certificate-chain PATH] [--private-key PATH] [--server-name NAME] \
     [--verify-peer] [--json-out PATH]"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_client_rr_request_args() {
        let config = parse_runtime_args([
            "client".to_owned(),
            "--mode".to_owned(),
            "rr".to_owned(),
            "--requests".to_owned(),
            "3".to_owned(),
            "--requests-in-flight".to_owned(),
            "2".to_owned(),
        ])
        .unwrap();

        assert_eq!(config.role, Role::Client);
        assert_eq!(config.mode, Mode::Rr);
        assert_eq!(config.requests, Some(3));
        assert_eq!(config.requests_in_flight, 2);
    }

    #[test]
    fn rejects_zero_streams() {
        let error =
            parse_runtime_args(["client".to_owned(), "--streams".to_owned(), "0".to_owned()])
                .unwrap_err();
        assert!(error.to_string().contains("usage:"));
    }

    #[test]
    fn parses_duration_suffixes() {
        assert_eq!(parse_duration("250ms").unwrap(), Duration::from_millis(250));
        assert_eq!(parse_duration("2s").unwrap(), Duration::from_secs(2));
    }
}

use crate::config::{
    congestion_control_name, direction_name, mode_name, Direction, Mode, PerfConfig,
    APPLICATION_PROTOCOL,
};
use crate::{PerfError, Result};
use serde::Serialize;
use std::cmp;
use std::fs;
use std::path::Path;
use std::time::Duration;

#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct LatencySummary {
    pub min_us: u64,
    pub avg_us: u64,
    pub p50_us: u64,
    pub p90_us: u64,
    pub p99_us: u64,
    pub max_us: u64,
}

#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct ServerCounters {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub requests_completed: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct RunSummary {
    pub schema_version: u32,
    pub status: String,
    pub mode: String,
    pub direction: String,
    pub backend: String,
    pub congestion_control: String,
    pub remote_host: String,
    pub remote_port: u16,
    pub alpn: String,
    pub elapsed_ms: u64,
    pub warmup_ms: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub server_counters: ServerCounters,
    pub requests_completed: u64,
    pub streams: usize,
    pub connections: usize,
    pub requests_in_flight: usize,
    pub request_bytes: usize,
    pub response_bytes: usize,
    pub throughput_mib_per_s: f64,
    pub throughput_gbit_per_s: f64,
    pub requests_per_s: f64,
    pub latency: LatencySummary,
    #[serde(skip)]
    pub latency_samples: Vec<Duration>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_reason: Option<String>,
}

pub fn new_run_summary(config: &PerfConfig) -> RunSummary {
    RunSummary {
        schema_version: 1,
        status: "ok".to_owned(),
        mode: mode_name(config.mode).to_owned(),
        direction: direction_name(config.direction).to_owned(),
        backend: "tokio".to_owned(),
        congestion_control: congestion_control_name(config.congestion_control).to_owned(),
        remote_host: config.host.clone(),
        remote_port: config.port,
        alpn: String::from_utf8_lossy(APPLICATION_PROTOCOL).into_owned(),
        elapsed_ms: 0,
        warmup_ms: duration_millis(config.warmup),
        bytes_sent: 0,
        bytes_received: 0,
        server_counters: ServerCounters::default(),
        requests_completed: 0,
        streams: config.streams,
        connections: config.connections,
        requests_in_flight: config.requests_in_flight,
        request_bytes: config.request_bytes,
        response_bytes: config.response_bytes,
        throughput_mib_per_s: 0.0,
        throughput_gbit_per_s: 0.0,
        requests_per_s: 0.0,
        latency: LatencySummary::default(),
        latency_samples: Vec::new(),
        failure_reason: None,
    }
}

pub fn reset_measurement(summary: &mut RunSummary) {
    summary.elapsed_ms = 0;
    summary.bytes_sent = 0;
    summary.bytes_received = 0;
    summary.server_counters = ServerCounters::default();
    summary.requests_completed = 0;
    summary.latency = LatencySummary::default();
    summary.latency_samples.clear();
    summary.throughput_mib_per_s = 0.0;
    summary.throughput_gbit_per_s = 0.0;
    summary.requests_per_s = 0.0;
}

pub fn finalize_summary(summary: &mut RunSummary) {
    summary.latency = summarize_latency_samples(summary.latency_samples.clone());
    let seconds = cmp::max(summary.elapsed_ms, 1) as f64 / 1000.0;
    let transfer_bytes = summary.bytes_sent + summary.bytes_received;
    summary.throughput_mib_per_s = transfer_bytes as f64 / (1024.0 * 1024.0) / seconds;
    summary.throughput_gbit_per_s = (transfer_bytes as f64 * 8.0) / 1_000_000_000.0 / seconds;
    summary.requests_per_s = summary.requests_completed as f64 / seconds;
}

pub fn emit_summary(summary: &RunSummary, json_out: Option<&Path>) -> Result<()> {
    println!("{}", render_summary(summary));
    if let Some(path) = json_out {
        let json = serde_json::to_string(summary)?;
        fs::write(path, json).map_err(|error| {
            PerfError::new(format!("failed to write {}: {error}", path.display()))
        })?;
    }
    Ok(())
}

pub fn render_summary(summary: &RunSummary) -> String {
    format!(
        "status={} mode={} cc={} direction={} throughput_mib/s={:.3} throughput_gbit/s={:.3} requests/s={:.3}",
        summary.status,
        summary.mode,
        summary.congestion_control,
        summary.direction,
        summary.throughput_mib_per_s,
        summary.throughput_gbit_per_s,
        summary.requests_per_s
    )
}

pub fn summarize_latency_samples(samples: Vec<Duration>) -> LatencySummary {
    if samples.is_empty() {
        return LatencySummary::default();
    }

    let mut micros: Vec<u64> = samples
        .iter()
        .map(|sample| duration_micros(*sample))
        .collect();
    micros.sort_unstable();
    let total: u128 = micros.iter().map(|value| *value as u128).sum();
    LatencySummary {
        min_us: micros[0],
        avg_us: (total / micros.len() as u128) as u64,
        p50_us: percentile_value(&micros, 50),
        p90_us: percentile_value(&micros, 90),
        p99_us: percentile_value(&micros, 99),
        max_us: micros[micros.len() - 1],
    }
}

pub fn mode_from_summary(summary: &RunSummary) -> Option<Mode> {
    match summary.mode.as_str() {
        "bulk" => Some(Mode::Bulk),
        "rr" => Some(Mode::Rr),
        "crr" => Some(Mode::Crr),
        _ => None,
    }
}

pub fn direction_from_summary(summary: &RunSummary) -> Option<Direction> {
    match summary.direction.as_str() {
        "upload" => Some(Direction::Upload),
        "download" => Some(Direction::Download),
        _ => None,
    }
}

pub fn duration_millis(duration: Duration) -> u64 {
    duration.as_millis().try_into().unwrap_or(u64::MAX)
}

pub fn duration_micros(duration: Duration) -> u64 {
    duration.as_micros().try_into().unwrap_or(u64::MAX)
}

fn percentile_value(sorted: &[u64], percentile: u64) -> u64 {
    let rank = ((percentile as f64 / 100.0) * sorted.len() as f64).ceil() as usize;
    let index = if rank == 0 {
        0
    } else {
        cmp::min(rank - 1, sorted.len() - 1)
    };
    sorted[index]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summarizes_latency_samples() {
        let summary = summarize_latency_samples(vec![
            Duration::from_micros(100),
            Duration::from_micros(300),
            Duration::from_micros(200),
        ]);
        assert_eq!(summary.min_us, 100);
        assert_eq!(summary.avg_us, 200);
        assert_eq!(summary.p50_us, 200);
        assert_eq!(summary.max_us, 300);
    }
}

//! Tokio perf runtime built on the `coquic-rs` QUIC facade.
//!
//! This crate mirrors the in-tree C++ `bench/coquic-perf` protocol while keeping
//! CoQUIC sans-I/O. Tokio owns UDP sockets and timers; `coquic-rs` owns QUIC
//! endpoint and connection state.

pub mod client;
pub mod config;
pub mod io;
pub mod metrics;
pub mod protocol;
pub mod server;

use std::error::Error;
use std::fmt;

pub type Result<T> = std::result::Result<T, PerfError>;

#[derive(Debug)]
pub struct PerfError {
    message: String,
}

impl PerfError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for PerfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl Error for PerfError {}

impl From<std::io::Error> for PerfError {
    fn from(value: std::io::Error) -> Self {
        Self::new(value.to_string())
    }
}

impl From<std::num::ParseIntError> for PerfError {
    fn from(value: std::num::ParseIntError) -> Self {
        Self::new(value.to_string())
    }
}

impl From<coquic::Status> for PerfError {
    fn from(value: coquic::Status) -> Self {
        Self::new(value.to_string())
    }
}

impl From<serde_json::Error> for PerfError {
    fn from(value: serde_json::Error) -> Self {
        Self::new(value.to_string())
    }
}

pub async fn run(config: config::PerfConfig) -> Result<metrics::RunSummary> {
    match config.role {
        config::Role::Server => server::run_server(config).await,
        config::Role::Client => client::run_client(config).await,
    }
}

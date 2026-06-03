//! Ergonomic Rust facade over CoQUIC.
//!
//! This crate builds on `coquic-sys` and keeps CoQUIC's sans-I/O contract:
//! callers own sockets, timers, routing, and scheduling.

pub use coquic_sys as sys;

pub mod quic;

pub use sys::ClientConnectionConfig;
pub use sys::{
    check_ffi_abi_version, http3, runtime_ffi_abi_version, AbiVersionMismatch, CloseConnection,
    CongestionControl, ConnectionHandle, ConnectionInput, EcnCodepoint, Effect, EndpointConfig,
    InboundDatagram, Lifecycle, LocalError, LocalErrorCode, MigrationReason, OpenConnection,
    PacketInspection, PacketInspectionDirection, PacketInspectionPacketType, PathMtuUpdate,
    PreferredAddress, QueryResult, RequestConnectionMigration, ResetStream, ResumptionState, Role,
    RouteHandle, SendDatagramData, SendStreamData, StateChange, Status, StopSending, StreamId,
    TimeUs, TlsIdentity, TransportConfig, ZeroRttConfig, ZeroRttStatus, FFI_ABI_VERSION,
};

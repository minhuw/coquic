use crate::{PerfError, Result};
use coquic::{EcnCodepoint, Effect, InboundDatagram, QueryResult, RouteHandle, TimeUs};
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::time;

const MAX_UDP_DATAGRAM_SIZE: usize = 64 * 1024;
const MAX_BUFFERED_SEND_DATAGRAMS: usize = 4096;

#[derive(Clone, Debug)]
struct Route {
    peer: SocketAddr,
    address_validation_identity: Vec<u8>,
}

#[derive(Debug)]
pub struct UdpRuntime {
    socket: UdpSocket,
    start: Instant,
    routes_by_handle: HashMap<RouteHandle, Route>,
    handles_by_peer: HashMap<SocketAddr, RouteHandle>,
    next_route_handle: RouteHandle,
    send_buffer: Vec<TxDatagram>,
    recv_buffer_size: usize,
}

#[derive(Clone, Debug)]
struct TxDatagram {
    route_handle: RouteHandle,
    bytes: Vec<u8>,
    ecn: EcnCodepoint,
    is_pmtu_probe: bool,
}

pub struct RxDatagram {
    pub bytes: Vec<u8>,
    pub route_handle: RouteHandle,
    pub address_validation_identity: Vec<u8>,
}

impl UdpRuntime {
    pub async fn client(
        host: &str,
        port: u16,
        recv_buffer_size: usize,
    ) -> Result<(Self, RouteHandle, Vec<u8>)> {
        let peer = resolve_remote(host, port)?;
        let bind_addr = if peer.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let socket = bind_udp_socket(bind_addr).await?;
        let mut runtime = Self::new(socket, recv_buffer_size);
        let route = runtime.ensure_route(peer);
        let identity = runtime
            .address_validation_identity(route)
            .ok_or_else(|| PerfError::new("missing client primary route identity"))?
            .to_vec();
        Ok((runtime, route, identity))
    }

    pub async fn server(host: &str, port: u16, recv_buffer_size: usize) -> Result<Self> {
        let bind_addr = format!("{host}:{port}");
        let socket = bind_udp_socket(&bind_addr).await?;
        Ok(Self::new(socket, recv_buffer_size))
    }

    pub fn now_us(&self) -> TimeUs {
        self.start
            .elapsed()
            .as_micros()
            .try_into()
            .unwrap_or(u64::MAX)
    }

    pub fn ensure_route(&mut self, peer: SocketAddr) -> RouteHandle {
        if let Some(handle) = self.handles_by_peer.get(&peer) {
            return *handle;
        }

        let handle = self.next_route_handle;
        self.next_route_handle += 1;
        self.handles_by_peer.insert(peer, handle);
        self.routes_by_handle.insert(
            handle,
            Route {
                peer,
                address_validation_identity: address_validation_identity(peer),
            },
        );
        handle
    }

    pub fn inbound_datagram<'a>(&'a self, rx: &'a RxDatagram) -> InboundDatagram<'a> {
        InboundDatagram {
            bytes: rx.bytes.as_slice(),
            route_handle: Some(rx.route_handle),
            address_validation_identity: rx.address_validation_identity.as_slice(),
            ecn: EcnCodepoint::Unavailable,
        }
    }

    pub fn collect_result_effects(&mut self, result: &QueryResult) -> Result<Vec<OwnedEffect>> {
        let mut out = Vec::new();
        for effect in result.effects() {
            match effect? {
                Effect::SendDatagram {
                    route_handle,
                    bytes,
                    ecn,
                    is_pmtu_probe,
                    ..
                } => {
                    if self.send_buffer.len() >= MAX_BUFFERED_SEND_DATAGRAMS {
                        return Err(PerfError::new(
                            "send buffer exceeded before flush; call flush_sends more often",
                        ));
                    }
                    let route_handle = route_handle
                        .ok_or_else(|| PerfError::new("send datagram missing route handle"))?;
                    self.send_buffer.push(TxDatagram {
                        route_handle,
                        bytes: bytes.to_vec(),
                        ecn,
                        is_pmtu_probe,
                    });
                }
                Effect::ReceiveStreamData {
                    connection,
                    stream_id,
                    bytes,
                    fin,
                } => out.push(OwnedEffect::ReceiveStreamData {
                    connection,
                    stream_id,
                    bytes: bytes.to_vec(),
                    fin,
                }),
                Effect::StateEvent { connection, change } => {
                    out.push(OwnedEffect::StateEvent { connection, change });
                }
                Effect::ConnectionLifecycleEvent { connection, event } => {
                    out.push(OwnedEffect::ConnectionLifecycleEvent { connection, event });
                }
                Effect::PeerResetStream {
                    connection,
                    stream_id,
                    application_error_code,
                    final_size,
                } => out.push(OwnedEffect::PeerResetStream {
                    connection,
                    stream_id,
                    application_error_code,
                    final_size,
                }),
                Effect::PeerStopSending {
                    connection,
                    stream_id,
                    application_error_code,
                } => out.push(OwnedEffect::PeerStopSending {
                    connection,
                    stream_id,
                    application_error_code,
                }),
                Effect::ReceiveDatagramData { .. }
                | Effect::PeerPreferredAddressAvailable { .. }
                | Effect::ResumptionStateAvailable { .. }
                | Effect::ZeroRttStatusEvent { .. }
                | Effect::PacketInspection(_)
                | Effect::NewTokenAvailable { .. }
                | Effect::Unknown(_) => {}
            }
        }
        Ok(out)
    }

    pub async fn flush_sends(&mut self) -> Result<()> {
        let datagrams = std::mem::take(&mut self.send_buffer);
        for datagram in datagrams {
            let route = self
                .routes_by_handle
                .get(&datagram.route_handle)
                .ok_or_else(|| {
                    PerfError::new(format!("unknown route handle {}", datagram.route_handle))
                })?;
            let _ = (datagram.ecn, datagram.is_pmtu_probe);
            self.socket.send_to(&datagram.bytes, route.peer).await?;
        }
        Ok(())
    }

    pub async fn recv(&mut self) -> io::Result<RxDatagram> {
        let mut buffer = vec![0u8; self.recv_buffer_size];
        let (len, peer) = self.socket.recv_from(&mut buffer).await?;
        buffer.truncate(len);
        let route_handle = self.ensure_route(peer);
        let address_validation_identity = self
            .address_validation_identity(route_handle)
            .unwrap_or_default()
            .to_vec();
        Ok(RxDatagram {
            bytes: buffer,
            route_handle,
            address_validation_identity,
        })
    }

    pub async fn wait(
        &mut self,
        next_wakeup: Option<TimeUs>,
        idle_timeout: Duration,
    ) -> Result<WaitEvent> {
        let timer_timeout = match next_wakeup {
            Some(wakeup) => {
                let now = self.now_us();
                if wakeup <= now {
                    return Ok(WaitEvent::Timer);
                }
                Some(Duration::from_micros(wakeup - now))
            }
            None => None,
        };
        let timeout = timer_timeout.unwrap_or(idle_timeout);

        match time::timeout(timeout, self.recv()).await {
            Ok(Ok(datagram)) => Ok(WaitEvent::Datagram(datagram)),
            Ok(Err(error)) => Err(error.into()),
            Err(_) if timer_timeout.is_some() => Ok(WaitEvent::Timer),
            Err(_) => Ok(WaitEvent::Idle),
        }
    }

    fn new(socket: UdpSocket, recv_buffer_size: usize) -> Self {
        Self {
            socket,
            start: Instant::now(),
            routes_by_handle: HashMap::new(),
            handles_by_peer: HashMap::new(),
            next_route_handle: 1,
            send_buffer: Vec::new(),
            recv_buffer_size: recv_buffer_size.clamp(1, MAX_UDP_DATAGRAM_SIZE),
        }
    }

    fn address_validation_identity(&self, route_handle: RouteHandle) -> Option<&[u8]> {
        self.routes_by_handle
            .get(&route_handle)
            .map(|route| route.address_validation_identity.as_slice())
    }
}

async fn bind_udp_socket(addr: &str) -> io::Result<UdpSocket> {
    let socket = UdpSocket::bind(addr).await?;
    configure_no_ip_fragmentation(&socket)?;
    Ok(socket)
}

#[cfg(target_os = "linux")]
fn configure_no_ip_fragmentation(socket: &UdpSocket) -> io::Result<()> {
    let fd = socket.as_raw_fd();
    let discover = libc::IP_PMTUDISC_PROBE;

    set_socket_option(fd, libc::IPPROTO_IP, libc::IP_MTU_DISCOVER, discover)?;
    set_socket_option(
        fd,
        libc::IPPROTO_IPV6,
        libc::IPV6_MTU_DISCOVER,
        libc::IPV6_PMTUDISC_PROBE,
    )?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn set_socket_option(
    fd: libc::c_int,
    level: libc::c_int,
    name: libc::c_int,
    value: libc::c_int,
) -> io::Result<()> {
    let result = unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            &value as *const _ as *const libc::c_void,
            std::mem::size_of_val(&value) as libc::socklen_t,
        )
    };
    if result == 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    if matches!(
        error.raw_os_error(),
        Some(libc::ENOPROTOOPT) | Some(libc::EINVAL)
    ) {
        return Ok(());
    }
    Err(error)
}

#[cfg(not(target_os = "linux"))]
fn configure_no_ip_fragmentation(_socket: &UdpSocket) -> io::Result<()> {
    Ok(())
}

pub enum WaitEvent {
    Datagram(RxDatagram),
    Timer,
    Idle,
}

#[derive(Clone, Debug)]
pub enum OwnedEffect {
    ReceiveStreamData {
        connection: coquic::ConnectionHandle,
        stream_id: coquic::StreamId,
        bytes: Vec<u8>,
        fin: bool,
    },
    StateEvent {
        connection: coquic::ConnectionHandle,
        change: coquic::StateChange,
    },
    ConnectionLifecycleEvent {
        connection: coquic::ConnectionHandle,
        event: coquic::Lifecycle,
    },
    PeerResetStream {
        connection: coquic::ConnectionHandle,
        stream_id: coquic::StreamId,
        application_error_code: u64,
        final_size: u64,
    },
    PeerStopSending {
        connection: coquic::ConnectionHandle,
        stream_id: coquic::StreamId,
        application_error_code: u64,
    },
}

fn resolve_remote(host: &str, port: u16) -> Result<SocketAddr> {
    let mut addrs = (host, port).to_socket_addrs()?;
    addrs
        .next()
        .ok_or_else(|| PerfError::new("failed to resolve remote address"))
}

fn address_validation_identity(peer: SocketAddr) -> Vec<u8> {
    match peer.ip() {
        IpAddr::V4(address) => {
            let mut identity = Vec::with_capacity(1 + 4 + 2);
            identity.push(0x04);
            identity.extend_from_slice(&address.octets());
            identity.extend_from_slice(&peer.port().to_be_bytes());
            identity
        }
        IpAddr::V6(address) => {
            let mut identity = Vec::with_capacity(1 + 16 + 2);
            identity.push(0x06);
            identity.extend_from_slice(&address.octets());
            identity.extend_from_slice(&peer.port().to_be_bytes());
            identity
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_validation_identity_matches_socket_layout() {
        let identity = address_validation_identity("127.0.0.1:4433".parse().unwrap());
        assert_eq!(identity, vec![0x04, 127, 0, 0, 1, 0x11, 0x51]);
    }

    #[tokio::test]
    async fn wait_reports_timer_when_future_timer_is_scheduled() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut runtime = UdpRuntime::new(socket, MAX_UDP_DATAGRAM_SIZE);
        let event = runtime
            .wait(
                Some(runtime.now_us() + Duration::from_millis(10).as_micros() as u64),
                Duration::from_millis(1),
            )
            .await
            .unwrap();

        assert!(matches!(event, WaitEvent::Timer));
    }

    #[tokio::test]
    async fn wait_reports_idle_when_no_timer_is_scheduled() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut runtime = UdpRuntime::new(socket, MAX_UDP_DATAGRAM_SIZE);
        let event = runtime.wait(None, Duration::from_millis(1)).await.unwrap();

        assert!(matches!(event, WaitEvent::Idle));
    }
}

use crate::{
    CloseConnection, ConnectionHandle, ConnectionInput, InboundDatagram, OpenConnection,
    PathMtuUpdate, QueryResult, RequestConnectionMigration, ResetStream, SendDatagramData,
    SendStreamData, Status, StopSending, StreamId, TimeUs,
};
use std::cell::RefCell;
use std::rc::{Rc, Weak};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EndpointConfig {
    pub core: crate::EndpointConfig,
}

impl Default for EndpointConfig {
    fn default() -> Self {
        Self {
            core: crate::EndpointConfig::default(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientConfig {
    pub core: crate::ClientConnectionConfig,
    pub initial_route_handle: crate::RouteHandle,
    pub address_validation_identity: Vec<u8>,
}

impl ClientConfig {
    pub fn new(
        source_connection_id: impl Into<Vec<u8>>,
        initial_destination_connection_id: impl Into<Vec<u8>>,
    ) -> Self {
        let mut core = crate::ClientConnectionConfig::default();
        core.source_connection_id = source_connection_id.into();
        core.initial_destination_connection_id = initial_destination_connection_id.into();
        Self {
            core,
            initial_route_handle: 0,
            address_validation_identity: Vec::new(),
        }
    }

    fn to_open_connection(&self) -> OpenConnection {
        OpenConnection {
            connection: self.core.clone(),
            initial_route_handle: self.initial_route_handle,
            address_validation_identity: self.address_validation_identity.clone(),
        }
    }
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            core: crate::ClientConnectionConfig::default(),
            initial_route_handle: 0,
            address_validation_identity: Vec::new(),
        }
    }
}

pub struct Endpoint {
    inner: Rc<RefCell<coquic_sys::Endpoint>>,
}

impl Endpoint {
    pub fn new(config: &EndpointConfig) -> Result<Self, Status> {
        let endpoint = coquic_sys::Endpoint::new(&config.core)?;
        Ok(Self {
            inner: Rc::new(RefCell::new(endpoint)),
        })
    }

    pub fn connect(&mut self, config: ClientConfig, now: TimeUs) -> Result<ConnectResult, Status> {
        let open = config.to_open_connection();
        let (handle, result) = self.inner.borrow_mut().quic_connect(&open, now)?;
        Ok(ConnectResult {
            connection: self.connection(handle),
            result,
        })
    }

    pub fn connection(&self, handle: ConnectionHandle) -> Connection {
        Connection {
            endpoint: Rc::downgrade(&self.inner),
            handle,
        }
    }

    pub fn receive_datagram(
        &mut self,
        datagram: InboundDatagram<'_>,
        now: TimeUs,
    ) -> Result<QueryResult, Status> {
        self.inner.borrow_mut().quic_receive_datagram(datagram, now)
    }

    pub fn update_path_mtu(
        &mut self,
        update: &PathMtuUpdate,
        now: TimeUs,
    ) -> Result<QueryResult, Status> {
        self.inner.borrow_mut().quic_update_path_mtu(update, now)
    }

    pub fn timer_expired(&mut self, now: TimeUs) -> Result<QueryResult, Status> {
        self.inner.borrow_mut().quic_timer_expired(now)
    }

    pub fn connection_count(&self) -> usize {
        self.inner.borrow().connection_count()
    }

    pub fn next_wakeup(&self) -> Option<TimeUs> {
        self.inner.borrow().next_wakeup()
    }

    pub fn has_send_continuation_pending(&self) -> bool {
        self.inner.borrow().has_send_continuation_pending()
    }

    pub fn has_pending_stream_send(&self) -> bool {
        self.inner.borrow().has_pending_stream_send()
    }
}

pub struct ConnectResult {
    pub connection: Connection,
    pub result: QueryResult,
}

#[derive(Clone)]
pub struct Connection {
    endpoint: Weak<RefCell<coquic_sys::Endpoint>>,
    handle: ConnectionHandle,
}

impl Connection {
    pub fn handle(&self) -> ConnectionHandle {
        self.handle
    }

    pub fn is_valid(&self) -> bool {
        self.handle != 0 && self.endpoint.strong_count() != 0
    }

    pub fn stream(&self, stream_id: StreamId) -> Stream {
        Stream {
            connection: self.clone(),
            stream_id,
        }
    }

    pub fn advance(&self, input: ConnectionInput<'_>, now: TimeUs) -> Result<QueryResult, Status> {
        self.with_endpoint(|endpoint| endpoint.quic_connection_advance(self.handle, input, now))
    }

    pub fn send_stream(
        &self,
        stream_id: StreamId,
        bytes: &[u8],
        fin: bool,
        now: TimeUs,
    ) -> Result<QueryResult, Status> {
        self.with_endpoint(|endpoint| {
            endpoint.quic_connection_send_stream(
                self.handle,
                SendStreamData {
                    stream_id,
                    bytes,
                    fin,
                    priority: 0,
                },
                now,
            )
        })
    }

    pub fn send_datagram(&self, bytes: &[u8], now: TimeUs) -> Result<QueryResult, Status> {
        self.with_endpoint(|endpoint| {
            endpoint.quic_connection_send_datagram(
                self.handle,
                SendDatagramData { bytes, priority: 0 },
                now,
            )
        })
    }

    pub fn reset_stream(
        &self,
        stream_id: StreamId,
        application_error_code: u64,
        now: TimeUs,
    ) -> Result<QueryResult, Status> {
        self.with_endpoint(|endpoint| {
            endpoint.quic_connection_reset_stream(
                self.handle,
                &ResetStream {
                    stream_id,
                    application_error_code,
                },
                now,
            )
        })
    }

    pub fn stop_sending(
        &self,
        stream_id: StreamId,
        application_error_code: u64,
        now: TimeUs,
    ) -> Result<QueryResult, Status> {
        self.with_endpoint(|endpoint| {
            endpoint.quic_connection_stop_sending(
                self.handle,
                &StopSending {
                    stream_id,
                    application_error_code,
                },
                now,
            )
        })
    }

    pub fn close(
        &self,
        application_error_code: u64,
        reason_phrase: &[u8],
        now: TimeUs,
    ) -> Result<QueryResult, Status> {
        self.with_endpoint(|endpoint| {
            endpoint.quic_connection_close(
                self.handle,
                CloseConnection {
                    application_error_code,
                    reason_phrase,
                },
                now,
            )
        })
    }

    pub fn request_key_update(&self, now: TimeUs) -> Result<QueryResult, Status> {
        self.with_endpoint(|endpoint| endpoint.quic_connection_request_key_update(self.handle, now))
    }

    pub fn request_migration(
        &self,
        migration: RequestConnectionMigration<'_>,
        now: TimeUs,
    ) -> Result<QueryResult, Status> {
        self.with_endpoint(|endpoint| {
            endpoint.connection_request_migration(self.handle, migration, now)
        })
    }

    fn with_endpoint<T>(
        &self,
        call: impl FnOnce(&mut coquic_sys::Endpoint) -> Result<T, Status>,
    ) -> Result<T, Status> {
        let endpoint = self.endpoint.upgrade().ok_or(Status::InvalidArgument)?;
        let mut endpoint = endpoint
            .try_borrow_mut()
            .map_err(|_| Status::InvalidArgument)?;
        call(&mut endpoint)
    }
}

#[derive(Clone)]
pub struct Stream {
    connection: Connection,
    stream_id: StreamId,
}

impl Stream {
    pub fn id(&self) -> StreamId {
        self.stream_id
    }

    pub fn is_valid(&self) -> bool {
        self.connection.is_valid()
    }

    pub fn send(&self, bytes: &[u8], fin: bool, now: TimeUs) -> Result<QueryResult, Status> {
        self.connection.send_stream(self.stream_id, bytes, fin, now)
    }

    pub fn finish(&self, now: TimeUs) -> Result<QueryResult, Status> {
        self.send(&[], true, now)
    }

    pub fn reset(&self, application_error_code: u64, now: TimeUs) -> Result<QueryResult, Status> {
        self.connection
            .reset_stream(self.stream_id, application_error_code, now)
    }

    pub fn stop_sending(
        &self,
        application_error_code: u64,
        now: TimeUs,
    ) -> Result<QueryResult, Status> {
        self.connection
            .stop_sending(self.stream_id, application_error_code, now)
    }
}

impl std::fmt::Debug for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Endpoint")
            .field("connection_count", &self.connection_count())
            .finish()
    }
}

impl std::fmt::Debug for Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connection")
            .field("handle", &self.handle)
            .field("is_valid", &self.is_valid())
            .finish()
    }
}

impl std::fmt::Debug for Stream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Stream")
            .field("stream_id", &self.stream_id)
            .field("is_valid", &self.is_valid())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Effect, Role};

    #[test]
    fn connect_returns_connection_handle_and_effects() {
        let mut endpoint_config = EndpointConfig::default();
        endpoint_config.core.role = Role::Client;
        endpoint_config.core.verify_peer = false;

        let mut endpoint = Endpoint::new(&endpoint_config).unwrap();
        let mut client = ClientConfig::new([0xc1, 0x11], [0x83, 0x11]);
        client.initial_route_handle = 7;

        let connected = endpoint.connect(client, 0).unwrap();
        assert_eq!(connected.connection.handle(), 1);
        assert!(connected.connection.is_valid());

        let mut saw_created = false;
        let mut saw_send_datagram = false;
        for effect in connected.result.effects() {
            match effect.unwrap() {
                Effect::ConnectionLifecycleEvent { connection, event } => {
                    saw_created |= connection == 1 && event == crate::Lifecycle::Created;
                }
                Effect::SendDatagram {
                    connection,
                    route_handle,
                    bytes,
                    ..
                } => {
                    saw_send_datagram |=
                        connection == 1 && route_handle == Some(7) && !bytes.is_empty();
                }
                _ => {}
            }
        }

        assert!(saw_created);
        assert!(saw_send_datagram);
        assert_eq!(endpoint.connection_count(), 1);
    }

    #[test]
    fn connection_and_stream_methods_forward_to_facade() {
        let mut endpoint = Endpoint::new(&EndpointConfig::default()).unwrap();
        let connected = endpoint
            .connect(ClientConfig::new([0xc1, 0x12], [0x83, 0x12]), 0)
            .unwrap();

        let stream = connected.connection.stream(0);
        assert_eq!(stream.id(), 0);
        let result = stream.send(b"hello", true, 1).unwrap();
        assert_eq!(result.effect_count(), 0);

        let result = connected.connection.request_key_update(2).unwrap();
        assert!(result.local_error().unwrap().is_none());
    }

    #[test]
    fn stale_connection_handle_is_invalid_argument() {
        let connection = {
            let endpoint = Endpoint::new(&EndpointConfig::default()).unwrap();
            endpoint.connection(1)
        };

        assert!(!connection.is_valid());
        let error = match connection.request_key_update(0) {
            Ok(_) => panic!("stale connection unexpectedly succeeded"),
            Err(error) => error,
        };
        assert_eq!(error, Status::InvalidArgument);
    }
}

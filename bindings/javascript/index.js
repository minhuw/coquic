import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const packageRoot = path.dirname(fileURLToPath(import.meta.url));
const native = loadNative();

export const FFI_ABI_VERSION = 5;

export const Status = Object.freeze({
  OK: 0,
  INVALID_ARGUMENT: 1,
  OUT_OF_MEMORY: 2,
  INTERNAL_ERROR: 3,
});

export const Role = Object.freeze({
  CLIENT: 0,
  SERVER: 1,
});

export const CongestionControl = Object.freeze({
  NEWRENO: 0,
  CUBIC: 1,
  BBR: 2,
  COPA: 3,
  PCC: 4,
  PCC_VIVACE: 5,
});

export const EcnCodepoint = Object.freeze({
  UNAVAILABLE: 0,
  NOT_ECT: 1,
  ECT0: 2,
  ECT1: 3,
  CE: 4,
});

export const StateChange = Object.freeze({
  HANDSHAKE_READY: 0,
  HANDSHAKE_CONFIRMED: 1,
  FAILED: 2,
});

export const LocalErrorCode = Object.freeze({
  UNSUPPORTED_OPERATION: 0,
  INVALID_STREAM_ID: 1,
  INVALID_STREAM_DIRECTION: 2,
  SEND_SIDE_CLOSED: 3,
  RECEIVE_SIDE_CLOSED: 4,
  FINAL_SIZE_CONFLICT: 5,
  DATAGRAM_NOT_SUPPORTED: 6,
  DATAGRAM_TOO_LARGE: 7,
});

export const Lifecycle = Object.freeze({
  CREATED: 0,
  ACCEPTED: 1,
  CLOSED: 2,
});

export const MigrationReason = Object.freeze({
  ACTIVE: 0,
  PREFERRED_ADDRESS: 1,
});

export const ZeroRttStatus = Object.freeze({
  UNAVAILABLE: 0,
  NOT_ATTEMPTED: 1,
  ATTEMPTED: 2,
  ACCEPTED: 3,
  REJECTED: 4,
});

export const PacketInspectionDirection = Object.freeze({
  OUTBOUND: 0,
  INBOUND: 1,
});

export const PacketInspectionPacketType = Object.freeze({
  INITIAL: 0,
  ZERO_RTT: 1,
  HANDSHAKE: 2,
  ONE_RTT: 3,
});

export function TlsIdentity({
  certificatePem = Buffer.alloc(0),
  privateKeyPem = Buffer.alloc(0),
} = {}) {
  this.certificatePem = toBuffer(certificatePem);
  this.privateKeyPem = toBuffer(privateKeyPem);
}

export function ZeroRttConfig({
  attempt = false,
  allow = false,
  applicationContext = Buffer.alloc(0),
} = {}) {
  this.attempt = Boolean(attempt);
  this.allow = Boolean(allow);
  this.applicationContext = toBuffer(applicationContext);
}

export function OrphanZeroRttBufferConfig({
  maxPackets = 0,
  maxBytes = 0,
  maxAgeUs = 0n,
} = {}) {
  this.maxPackets = Number(maxPackets);
  this.maxBytes = Number(maxBytes);
  this.maxAgeUs = BigInt(maxAgeUs);
}

export function TransportConfig(values = {}) {
  Object.assign(this, native.defaultTransportConfig(), values);
}

export function EndpointConfig(values = {}) {
  const defaults = native.defaultEndpointConfig();
  Object.assign(this, defaults, values);
  this.supportedVersions = Array.from(values.supportedVersions ?? defaults.supportedVersions);
  this.applicationProtocol = toBuffer(values.applicationProtocol ?? defaults.applicationProtocol);
  this.identity = values.identity == null ? null : new TlsIdentity(values.identity);
  this.transport = new TransportConfig(values.transport ?? defaults.transport);
  this.zeroRtt = new ZeroRttConfig(values.zeroRtt ?? defaults.zeroRtt);
  this.orphanZeroRttBuffer = new OrphanZeroRttBufferConfig(
    values.orphanZeroRttBuffer ?? defaults.orphanZeroRttBuffer,
  );
}

export function ResumptionState({ serialized = Buffer.alloc(0) } = {}) {
  this.serialized = toBuffer(serialized);
}

export function ClientConnectionConfig(values = {}) {
  const defaults = native.defaultClientConnectionConfig();
  Object.assign(this, defaults, values);
  this.sourceConnectionId = toBuffer(
    values.sourceConnectionId ?? defaults.sourceConnectionId,
  );
  this.initialDestinationConnectionId = toBuffer(
    values.initialDestinationConnectionId ?? defaults.initialDestinationConnectionId,
  );
  this.originalDestinationConnectionId =
    values.originalDestinationConnectionId == null
      ? null
      : toBuffer(values.originalDestinationConnectionId);
  this.retrySourceConnectionId =
    values.retrySourceConnectionId == null ? null : toBuffer(values.retrySourceConnectionId);
  this.retryToken = toBuffer(values.retryToken ?? defaults.retryToken);
  this.serverName = toBuffer(values.serverName ?? defaults.serverName);
  this.resumptionState =
    values.resumptionState == null ? null : new ResumptionState(values.resumptionState);
  this.zeroRtt = new ZeroRttConfig(values.zeroRtt ?? defaults.zeroRtt);
}

export class ClientConfig {
  constructor({
    core = new ClientConnectionConfig(),
    initialRouteHandle = 0n,
    addressValidationIdentity = Buffer.alloc(0),
  } = {}) {
    this.core = core instanceof ClientConnectionConfig ? core : new ClientConnectionConfig(core);
    this.initialRouteHandle = initialRouteHandle;
    this.addressValidationIdentity = toBuffer(addressValidationIdentity);
  }

  static new(sourceConnectionId, initialDestinationConnectionId) {
    return new ClientConfig({
      core: new ClientConnectionConfig({
        sourceConnectionId,
        initialDestinationConnectionId,
      }),
    });
  }

  toOpenConnection() {
    return {
      connection: this.core,
      initialRouteHandle: this.initialRouteHandle,
      addressValidationIdentity: this.addressValidationIdentity,
    };
  }
}

export function InboundDatagram({
  bytes,
  routeHandle = null,
  addressValidationIdentity = Buffer.alloc(0),
  ecn = EcnCodepoint.UNAVAILABLE,
}) {
  this.bytes = toBuffer(bytes);
  this.routeHandle = routeHandle;
  this.addressValidationIdentity = toBuffer(addressValidationIdentity);
  this.ecn = ecn;
}

export class Endpoint {
  constructor(config = new EndpointConfig()) {
    this._native = new native.Endpoint(normalizeEndpointConfig(config));
  }

  close() {
    this._native.close();
  }

  connect(config, now) {
    const out = this._native.connect(config.toOpenConnection(), now);
    return {
      connection: this.connection(out.connection),
      result: out.result,
    };
  }

  connection(handle) {
    return new Connection(this, handle);
  }

  receiveDatagram(datagram, now) {
    return this._native.receiveDatagram(datagram, now);
  }

  receive_datagram(datagram, now) {
    return this.receiveDatagram(datagram, now);
  }

  timerExpired(now) {
    return this._native.timerExpired(now);
  }

  timer_expired(now) {
    return this.timerExpired(now);
  }

  connectionCount() {
    return this._native.connectionCount();
  }

  connection_count() {
    return this.connectionCount();
  }

  nextWakeup() {
    return this._native.nextWakeup();
  }

  next_wakeup() {
    return this.nextWakeup();
  }

  hasSendContinuationPending() {
    return this._native.hasSendContinuationPending();
  }

  has_send_continuation_pending() {
    return this.hasSendContinuationPending();
  }

  hasPendingStreamSend() {
    return this._native.hasPendingStreamSend();
  }

  has_pending_stream_send() {
    return this.hasPendingStreamSend();
  }
}

export class Connection {
  constructor(endpoint, handle) {
    this._endpoint = endpoint;
    this.handle = handle;
  }

  stream(streamId) {
    return new Stream(this, streamId);
  }

  sendStream(streamId, data, fin, now, priority = 0) {
    return this._endpoint._native.sendStream(
      this.handle,
      streamId,
      toBuffer(data),
      fin,
      now,
      priority,
    );
  }

  sendDatagram(data, now, priority = 0) {
    return this._endpoint._native.sendDatagram(this.handle, toBuffer(data), now, priority);
  }

  close(applicationErrorCode, reasonPhrase = Buffer.alloc(0), now) {
    return this._endpoint._native.closeConnection(
      this.handle,
      applicationErrorCode,
      toBuffer(reasonPhrase),
      now,
    );
  }
}

export class Stream {
  constructor(connection, streamId) {
    this._connection = connection;
    this.id = streamId;
  }

  send(data, fin, now, priority = 0) {
    return this._connection.sendStream(this.id, data, fin, now, priority);
  }

  finish(now) {
    return this.send(Buffer.alloc(0), true, now);
  }
}

export function ffiAbiVersion() {
  return native.ffiAbiVersion();
}

export const quic = Object.freeze({
  Endpoint,
  EndpointConfig,
  OrphanZeroRttBufferConfig,
  ClientConfig,
  ClientConnectionConfig,
  Connection,
  Stream,
  InboundDatagram,
});

function normalizeEndpointConfig(config) {
  const normalized = config instanceof EndpointConfig ? config : new EndpointConfig(config);
  return {
    ...normalized,
    applicationProtocol: toBuffer(normalized.applicationProtocol),
    identity:
      normalized.identity == null
        ? null
        : {
            certificatePem: toBuffer(normalized.identity.certificatePem),
            privateKeyPem: toBuffer(normalized.identity.privateKeyPem),
          },
    transport: { ...normalized.transport },
    zeroRtt: {
      ...normalized.zeroRtt,
      applicationContext: toBuffer(normalized.zeroRtt.applicationContext),
    },
  };
}

function toBuffer(value) {
  if (Buffer.isBuffer(value)) {
    return value;
  }
  if (value == null) {
    return Buffer.alloc(0);
  }
  if (typeof value === "string") {
    return Buffer.from(value);
  }
  return Buffer.from(value);
}

function loadNative() {
  const errors = [];
  try {
    return require("./native/coquic_js.node");
  } catch (error) {
    errors.push(`${path.join(packageRoot, "native", "coquic_js.node")}: ${error.message}`);
  }

  try {
    return require("./build/Release/coquic_js.node");
  } catch (error) {
    errors.push(
      `${path.join(packageRoot, "build", "Release", "coquic_js.node")}: ${error.message}`,
    );
  }

  throw new Error(`failed to load CoQUIC native addon:\n${errors.join("\n")}`);
}

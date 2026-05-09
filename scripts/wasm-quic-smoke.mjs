#!/usr/bin/env node

import fs from "node:fs";
import { webcrypto } from "node:crypto";

globalThis.crypto ??= webcrypto;

const wasmPath = process.argv[2] ?? "zig-out/bin/coquic-wasm-quic.wasm";
const bytes = fs.readFileSync(wasmPath);
const debug = process.env.COQUIC_WASM_SMOKE_DEBUG === "1";

let instance;
const module = await WebAssembly.compile(bytes);
instance = await WebAssembly.instantiate(module, {
  wasi_snapshot_preview1: {
    args_get: () => 0,
    args_sizes_get: (argc, argvBufSize) => {
      dataView().setUint32(argc, 0, true);
      dataView().setUint32(argvBufSize, 0, true);
      return 0;
    },
    clock_time_get: (_clockId, _precision, time) => {
      dataView().setBigUint64(time, 0n, true);
      return 0;
    },
    environ_get: () => 0,
    environ_sizes_get: (environCount, environBufSize) => {
      dataView().setUint32(environCount, 0, true);
      dataView().setUint32(environBufSize, 0, true);
      return 0;
    },
    fd_close: () => 0,
    fd_fdstat_get: () => 8,
    fd_prestat_get: () => 8,
    fd_prestat_dir_name: () => 8,
    fd_read: () => 8,
    fd_seek: () => 8,
    fd_write: (_fd, _iovs, _iovsLen, nwritten) => {
      dataView().setUint32(nwritten, 0, true);
      return 0;
    },
    proc_exit: (code) => {
      throw new Error(`WASI proc_exit(${code})`);
    },
    random_get: (pointer, length) => {
      crypto.getRandomValues(new Uint8Array(instance.exports.memory.buffer, pointer, length));
      return 0;
    },
  },
});

const {
  memory,
  _initialize,
  coquic_wasm_alloc,
  coquic_wasm_free,
  coquic_wasm_endpoint_create,
  coquic_wasm_endpoint_destroy,
  coquic_wasm_endpoint_open_connection,
  coquic_wasm_endpoint_input_datagram,
  coquic_wasm_endpoint_send_stream,
  coquic_wasm_endpoint_timer_expired,
  coquic_wasm_endpoint_next_wakeup_ms,
  coquic_wasm_endpoint_next_datagram_header,
  coquic_wasm_endpoint_pop_datagram,
  coquic_wasm_endpoint_next_event_header,
  coquic_wasm_endpoint_pop_event,
  coquic_wasm_endpoint_next_packet_inspection_header,
  coquic_wasm_endpoint_pop_packet_inspection,
  coquic_wasm_endpoint_diagnostics,
} = instance.exports;

_initialize();

if (typeof coquic_wasm_endpoint_diagnostics !== "function") {
  throw new Error("missing coquic_wasm_endpoint_diagnostics export");
}

const eventTypes = {
  state: 1,
  lifecycle: 2,
  receiveStream: 3,
  localError: 4,
};
const stateCodes = {
  handshakeReady: 0,
  handshakeConfirmed: 1,
  failed: 2,
};

const certPem = `-----BEGIN CERTIFICATE-----
MIIDCTCCAfGgAwIBAgIUfGLiwBSFPX9DqQSNXv+f3CUruwswDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MDMxODEzMjIxNVoXDTI3MDMx
ODEzMjIxNVowFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEA/ilQZWcEKdgT7VAyku7JOVvmtJSk0/u2IJvEmfb7Cdbl
zt039tBRsiFrdFikSTGm7rBqCzzT7wAHv4J0+nP/tQs53uslpViTi7rVAvml/jHX
ng3JevgJzz3AdEpTTPL3NKjQESuNiXsuoutTzNJ1ltDywQz4+vGe9ctQye51TsBD
mr/fJAzult7m1PTroiTp7ZJkq6ybUhmT943fT40WGy1uk5LwVYmbh4sbzweVbIQp
RLT3YZeYG0Klocez2o3v5PMXE94eOBZGLVhYA1iwmubZpqtPfnMYFPApwoYdJfZ4
xOBT4eYqgzZu/Be9VR7KKX82eFViGhLg69lMSjR4KwIDAQABo1MwUTAdBgNVHQ4E
FgQUShGJTwym+VNTqADxkzCXDDXOTN8wHwYDVR0jBBgwFoAUShGJTwym+VNTqADx
kzCXDDXOTN8wDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAVOf+
NQ52+nRbePlhxeLVaIiQBKZcUCVkWcZfG6xpkrgF7OQXsPq7RzFzd/OFLuUXkEPR
G/jE+thaj+jytTXvTKmXPhQNoihem9r0HzaYJP7gL0tBc5hZjJDbwN7xNy77nTDD
EENFyvRWDs1Dn7lXJFoYSpYhbfqBw12uPfM1wyqNDnALcVpMZCkOWu9Xgeg2Qqr1
I4OQhcypFBscgLaILsmon74WpYGR1DygjufmAwVbRHw9B2Ep9XP/zVQNJ9bOnljw
c0PxBwkqi65cndFE++WVC2flc1hRRARfZejA/Xrg54vujrQ7xzUXCNGV+B1B4Svl
p+Y0wRfxl6nd2jrw7g==
-----END CERTIFICATE-----
`;

const keyPem = `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQD+KVBlZwQp2BPt
UDKS7sk5W+a0lKTT+7Ygm8SZ9vsJ1uXO3Tf20FGyIWt0WKRJMabusGoLPNPvAAe/
gnT6c/+1Czne6yWlWJOLutUC+aX+MdeeDcl6+AnPPcB0SlNM8vc0qNARK42Jey6i
61PM0nWW0PLBDPj68Z71y1DJ7nVOwEOav98kDO6W3ubU9OuiJOntkmSrrJtSGZP3
jd9PjRYbLW6TkvBViZuHixvPB5VshClEtPdhl5gbQqWhx7Paje/k8xcT3h44FkYt
WFgDWLCa5tmmq09+cxgU8CnChh0l9njE4FPh5iqDNm78F71VHsopfzZ4VWIaEuDr
2UxKNHgrAgMBAAECggEBAIxMoA2pxTmYBr/8gj5rw/Z+zaanWymNjGcJtYhMNx2i
W+9KXIdJTZ+oJRnviJjC6ORfy9nyNQd8m8pSqGJMwD3fOY3dfkV81M3QT5+50bC1
MNIVyD+yRi/5ZZCMKtmSUXXnLhwcT6AxuHfEsdih4LllFGwOzi4wTNBf8HPXxze1
fr4WCJ9J4PunT/WKjgHSqN30JsPupc0J2+MfbxKkmrUT+xsSCG51JTYM3xws+1pY
KEVtX2Rj74bWCf66lvSR2tBjhVpjvql1CR0n3uQ6ukPIPpD936t92gAAh1ah5LuM
q3jn8feFYdbjH7u1SPuxzPcHhS6nHs8cnTV9fOpUI0ECgYEA/9xSF18qCES0VLau
GHPBOIIgkqu3xXmIf4vBgIywWf1a+Tr6ABk2Kpe15CnLms9ozFjq5qlt9vFBGXL6
7JJcaHiVS+fRKhMyXPODEm8OR4UoX+sJE58LBj9lpfHTy7phzi+fUcS4jWBIMAGV
fqyK02E75bGQyS0rcwCW0vvc4csCgYEA/kzBpNS9peT2YrqsgCxeMmqqhIyGSKz1
MGE3iiVCwGvP+vmVK5adnhNHD1+wBRAoOv439Gpw6r7J6i3gOCXuaEr4ili3M9Ys
6dN3mFt6Q56KM0W5mF8qcEL3LSvv3YOaG5222eG94E2PA/3VomDN7bReNDyF2S8O
up5T/CCSdyECgYAjLfTvl7scxe2RlEidvhS8I1A9OnUbJtm4x8uEVFPPG8HNcOl8
5/qForR0ubZwA8KiDjvGGVewU32i9SdBLeKczq+gbzBYO6l6FFVaTIDHHqzte1CV
LRID+uWMCpMXePoHso6SXJ0Pe0SRrTYT4792zvDAZUjGEHrf5h3WxqCZPwKBgQC9
4kKV+eTCgv0XK5yy+G495zf8UZHTopJS1cTK+pelZtud489nBMgcyPg+moysuyvP
IRRXBUPbhSrwGeFbC7fBWHnNlAD4S+ytjKG4ulXJOBCpyF6VUDo4KUi4Ch7JoQLp
rBJlDxLg8gjgSiHDZdVesVfGWYr4aRLudlrv4MJ9AQKBgC6ru7V4pXSXhu0d1zdJ
I6+gmCCVlulCj89YpX9DN11IrLHD7p3g+vLfLFJEzSLjVJi/vF+avjnePOY58xg9
1vvDklAgaW7GxDoi8OgNVOj1mStu3sphJtTlzI8q2DqB0ICbJlwTKcjWcms2wVnd
rmZ1jkyEbwNB4p2YPXDQJ3hW
-----END PRIVATE KEY-----
`;

function view() {
  return new Uint8Array(memory.buffer);
}

function dataView() {
  return new DataView(memory.buffer);
}

function alloc(size) {
  const pointer = coquic_wasm_alloc(size);
  if (pointer === 0) {
    throw new Error(`malloc(${size}) failed`);
  }
  return pointer;
}

function allocBytes(input) {
  if (input.length === 0) {
    return 0;
  }
  const pointer = alloc(input.length);
  view().set(input, pointer);
  return pointer;
}

function withBytes(input, callback) {
  const pointer = allocBytes(input);
  try {
    return callback(pointer, input.length);
  } finally {
    if (pointer !== 0) {
      coquic_wasm_free(pointer);
    }
  }
}

function readBytes(pointer, length) {
  return new Uint8Array(view().slice(pointer, pointer + length));
}

function endpointDiagnostics(endpoint) {
  const pointer = alloc(65536);
  try {
    const written = checked(
      "endpoint diagnostics",
      coquic_wasm_endpoint_diagnostics(endpoint, pointer, 65536),
    );
    return JSON.parse(new TextDecoder().decode(readBytes(pointer, written)));
  } finally {
    coquic_wasm_free(pointer);
  }
}

function checked(label, value) {
  if (value < 0) {
    throw new Error(`${label} failed with ${value}`);
  }
  return value;
}

function jsonState(value) {
  return JSON.stringify(value, (_key, item) =>
    typeof item === "bigint" ? item.toString() : item,
  );
}

function debugLog(text) {
  if (debug) {
    console.error(text);
  }
}

function readHeader(size, callback) {
  const pointer = alloc(size);
  try {
    const status = callback(pointer, size);
    if (status < 0) {
      throw new Error(`header read failed with ${status}`);
    }
    if (status === 0) {
      return null;
    }
    return new DataView(view().slice(pointer, pointer + size).buffer);
  } finally {
    coquic_wasm_free(pointer);
  }
}

function popDatagram(endpoint) {
  const header = readHeader(40, (out, outLen) =>
    coquic_wasm_endpoint_next_datagram_header(endpoint, out, outLen),
  );
  if (header === null) {
    return null;
  }
  const datagram = {
    connection: header.getBigUint64(0, true),
    routeHandle: header.getBigUint64(8, true),
    hasRouteHandle: header.getUint32(16, true) !== 0,
    ecn: header.getUint32(20, true),
    length: header.getUint32(28, true),
    inspectionDatagramId: header.getBigUint64(32, true),
    bytes: new Uint8Array(),
  };
  const pointer = alloc(datagram.length);
  try {
    const written = checked(
      "pop datagram",
      coquic_wasm_endpoint_pop_datagram(endpoint, pointer, datagram.length),
    );
    datagram.bytes = readBytes(pointer, written);
  } finally {
    coquic_wasm_free(pointer);
  }
  return datagram;
}

function popEvent(endpoint) {
  const header = readHeader(48, (out, outLen) =>
    coquic_wasm_endpoint_next_event_header(endpoint, out, outLen),
  );
  if (header === null) {
    return null;
  }
  const event = {
    type: header.getUint32(0, true),
    code: header.getUint32(4, true),
    connection: header.getBigUint64(8, true),
    streamId: header.getBigUint64(16, true),
    fin: header.getUint32(24, true) !== 0,
    length: header.getUint32(28, true),
    value: header.getBigUint64(32, true),
    payload: new Uint8Array(),
  };
  const pointer = alloc(event.length);
  try {
    const written = checked(
      "pop event",
      coquic_wasm_endpoint_pop_event(endpoint, pointer, event.length),
    );
    event.payload = readBytes(pointer, written);
  } finally {
    coquic_wasm_free(pointer);
  }
  return event;
}

function popPacketInspection(endpoint) {
  const header = readHeader(48, (pointer, length) =>
    coquic_wasm_endpoint_next_packet_inspection_header(endpoint, pointer, length),
  );
  if (!header) return null;
  const length = header.getUint32(36, true);
  const pointer = coquic_wasm_alloc(length);
  try {
    const read = checked(
      "pop packet inspection",
      coquic_wasm_endpoint_pop_packet_inspection(endpoint, pointer, length),
    );
    const payload = readBytes(pointer, read);
    return JSON.parse(new TextDecoder().decode(payload));
  } finally {
    coquic_wasm_free(pointer);
  }
}

function drainPacketInspections(endpoint) {
  const inspections = [];
  for (;;) {
    const inspection = popPacketInspection(endpoint);
    if (!inspection) break;
    inspections.push(inspection);
  }
  return inspections;
}

function packetInspectionKey(endpoint, datagramId) {
  return `${endpoint}:${datagramId.toString()}`;
}

function rememberPacketInspections(endpoint, state) {
  for (const inspection of drainPacketInspections(endpoint)) {
    const key = packetInspectionKey(endpoint, BigInt(inspection.datagram_id));
    const existing = state.pendingPacketInspections.get(key) ?? [];
    existing.push(inspection);
    state.pendingPacketInspections.set(key, existing);
  }
}

function drainEvents(endpoint, label, state) {
  for (;;) {
    const event = popEvent(endpoint);
    if (event === null) {
      break;
    }
    debugLog(
      `event ${label} type=${event.type} code=${event.code} connection=${event.connection} stream=${event.streamId} fin=${event.fin} len=${event.payload.length}`,
    );
    if (event.type === eventTypes.localError) {
      throw new Error(`${label} local error code=${event.code} stream=${event.streamId}`);
    }
    if (event.type === eventTypes.state) {
      if (event.code === stateCodes.handshakeReady) {
        state[`${label}Ready`] = true;
      }
      if (event.code === stateCodes.handshakeConfirmed) {
        state[`${label}Confirmed`] = true;
      }
      if (event.code === stateCodes.failed) {
        throw new Error(`${label} QUIC state failed`);
      }
    }
    if (event.type === eventTypes.lifecycle && event.connection !== 0n) {
      state[`${label}Connection`] = event.connection;
    }
    if (event.type === eventTypes.receiveStream) {
      state.received.push({
        endpoint: label,
        streamId: event.streamId,
        fin: event.fin,
        text: new TextDecoder().decode(event.payload),
      });
    }
  }
}

function relay(from, to, routeHandle, now) {
  let moved = 0;
  for (;;) {
    const datagram = popDatagram(from);
    if (datagram === null) {
      break;
    }
    rememberPacketInspections(from, state);
    const inspectionKey = packetInspectionKey(from, datagram.inspectionDatagramId);
    const inspections = state.pendingPacketInspections.get(inspectionKey) ?? [];
    state.pendingPacketInspections.delete(inspectionKey);
    if (datagram.inspectionDatagramId !== 0n && inspections.length === 0) {
      throw new Error("datagram had inspection id but no inspection record");
    }
    state.packetInspections += inspections.length;
    state.inspectedFrames += inspections.reduce(
      (count, inspection) =>
        count + (Array.isArray(inspection.frames) ? inspection.frames.length : 0),
      0,
    );
    debugLog(
      `datagram ${from}->${to} len=${datagram.bytes.length} ecn=${datagram.ecn} route=${routeHandle}`,
    );
    withBytes(datagram.bytes, (pointer, length) => {
      checked(
        "input datagram",
        coquic_wasm_endpoint_input_datagram(to, now, pointer, length, routeHandle, datagram.ecn),
      );
    });
    moved += 1;
  }
  return moved;
}

function pump(client, server, state, now) {
  let moved = 0;
  moved += relay(client, server, 7n, now);
  moved += relay(server, client, 1n, now);
  drainEvents(client, "client", state);
  drainEvents(server, "server", state);
  return moved;
}

const encoder = new TextEncoder();
const certBytes = encoder.encode(certPem);
const keyBytes = encoder.encode(keyPem);

const client = coquic_wasm_endpoint_create(0, 0, 0, 0, 0);
const server = withBytes(certBytes, (certPointer, certLength) =>
  withBytes(keyBytes, (keyPointer, keyLength) =>
    coquic_wasm_endpoint_create(1, certPointer, certLength, keyPointer, keyLength),
  ),
);
debugLog(`endpoints client=${client} server=${server}`);
if (client === 0 || server === 0) {
  throw new Error(`endpoint creation failed client=${client} server=${server}`);
}

const state = {
  clientReady: false,
  clientConfirmed: false,
  serverReady: false,
  serverConfirmed: false,
  clientConnection: 0n,
  serverConnection: 0n,
  packetInspections: 0,
  inspectedFrames: 0,
  pendingPacketInspections: new Map(),
  received: [],
};

try {
  const emptyClientDiagnostics = endpointDiagnostics(client);
  if (emptyClientDiagnostics.role !== "client" || emptyClientDiagnostics.connection_count !== 0) {
    throw new Error(`unexpected empty client diagnostics ${jsonState(emptyClientDiagnostics)}`);
  }

  let now = 0n;
  const connection = coquic_wasm_endpoint_open_connection(client, now, 0, 0, 0, 0, 1n);
  debugLog(`open connection=${connection}`);
  if (connection <= 0) {
    throw new Error(`open connection failed with ${connection}`);
  }
  state.clientConnection = BigInt(connection);
  const openedClientDiagnostics = endpointDiagnostics(client);
  if (openedClientDiagnostics.connection_count !== 1) {
    throw new Error(`client diagnostics did not expose opened connection ${jsonState(openedClientDiagnostics)}`);
  }

  for (let step = 0; step < 96 && !(state.clientReady && state.serverConfirmed); step += 1) {
    now += 1n;
    const moved = pump(client, server, state, now);
    const clientWake = coquic_wasm_endpoint_next_wakeup_ms(client);
    const serverWake = coquic_wasm_endpoint_next_wakeup_ms(server);
    debugLog(
      `handshake step=${step} moved=${moved} clientWake=${clientWake} serverWake=${serverWake} state=${jsonState(state)}`,
    );
    if (moved === 0) {
      if (clientWake >= 0 && BigInt(clientWake) <= now) {
        checked("client timer", coquic_wasm_endpoint_timer_expired(client, now));
      }
      if (serverWake >= 0 && BigInt(serverWake) <= now) {
        checked("server timer", coquic_wasm_endpoint_timer_expired(server, now));
      }
    }
  }

  if (!state.clientReady || !state.serverConfirmed) {
    throw new Error(`handshake did not confirm: ${jsonState(state)}`);
  }
  if (state.serverConnection === 0n) {
    throw new Error("server did not emit an accepted connection handle");
  }

  const payload = encoder.encode("hello from wasm quic");
  withBytes(payload, (pointer, length) => {
    checked(
      "send stream",
      coquic_wasm_endpoint_send_stream(
        client,
        now,
        state.clientConnection,
        0n,
        pointer,
        length,
        1,
      ),
    );
  });

  for (let step = 0; step < 64 && state.received.length === 0; step += 1) {
    now += 1n;
    const moved = pump(client, server, state, now);
    debugLog(`stream step=${step} moved=${moved} state=${jsonState(state)}`);
    if (moved === 0) {
      const clientWake = coquic_wasm_endpoint_next_wakeup_ms(client);
      const serverWake = coquic_wasm_endpoint_next_wakeup_ms(server);
      if (clientWake >= 0 && BigInt(clientWake) <= now) {
        checked("client timer", coquic_wasm_endpoint_timer_expired(client, now));
      }
      if (serverWake >= 0 && BigInt(serverWake) <= now) {
        checked("server timer", coquic_wasm_endpoint_timer_expired(server, now));
      }
    }
  }

  const received = state.received.find((event) => event.endpoint === "server");
  if (received?.text !== "hello from wasm quic" || received.streamId !== 0n || !received.fin) {
    throw new Error(`unexpected receive event ${jsonState(state.received)}`);
  }
  if (state.packetInspections === 0 || state.inspectedFrames === 0) {
    throw new Error(`packet inspection did not produce frame records: ${jsonState(state)}`);
  }
  const serverDiagnostics = endpointDiagnostics(server);
  if (serverDiagnostics.connection_count !== 1 || serverDiagnostics.connections[0]?.active_streams === undefined) {
    throw new Error(`server diagnostics missing connection internals ${jsonState(serverDiagnostics)}`);
  }

  console.log("wasm-quic smoke ok");
} finally {
  coquic_wasm_endpoint_destroy(client);
  coquic_wasm_endpoint_destroy(server);
}

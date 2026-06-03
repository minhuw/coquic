#!/usr/bin/env node

import fs from "node:fs";
import { webcrypto } from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";

globalThis.crypto ??= webcrypto;

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
process.chdir(repoRoot);
const wasmPath = resolveRepoPath(
  process.argv[2] ?? "zig-out/share/wasm-quic/coquic-wasm-quic.wasm",
);
const bytes = readWasmArtifact(wasmPath);
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

function resolveRepoPath(inputPath) {
  const resolved = path.resolve(repoRoot, inputPath);
  const relative = path.relative(repoRoot, resolved);
  if (relative.startsWith("..") || path.isAbsolute(relative)) {
    throw new Error(`WASM smoke path escapes repository root: ${inputPath}`);
  }
  return resolved;
}

function readWasmArtifact(resolvedPath) {
  const relative = path.relative(repoRoot, resolvedPath);
  if (relative !== "zig-out/share/wasm-quic/coquic-wasm-quic.wasm") {
    throw new Error(`unsupported WASM smoke artifact path: ${relative}`);
  }
  return fs.readFileSync("zig-out/share/wasm-quic/coquic-wasm-quic.wasm");
}

const {
  memory,
  _initialize,
  coquic_wasm_alloc,
  coquic_wasm_free,
  coquic_wasm_endpoint_create,
  coquic_wasm_endpoint_create_with_options,
  coquic_wasm_endpoint_destroy,
  coquic_wasm_endpoint_open_connection,
  coquic_wasm_endpoint_open_connection_with_options,
  coquic_wasm_endpoint_open_connection_with_resumption,
  coquic_wasm_endpoint_input_datagram,
  coquic_wasm_endpoint_send_stream,
  coquic_wasm_endpoint_send_datagram,
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
for (const [name, fn] of Object.entries({
  coquic_wasm_endpoint_create_with_options,
  coquic_wasm_endpoint_open_connection_with_options,
  coquic_wasm_endpoint_open_connection_with_resumption,
})) {
  if (typeof fn !== "function") {
    throw new Error(`missing ${name} export`);
  }
}

const eventTypes = {
  state: 1,
  lifecycle: 2,
  receiveStream: 3,
  localError: 4,
  zeroRttStatus: 7,
  resumptionStateAvailable: 8,
  receiveDatagram: 10,
};
const zeroRttStatusCodes = {
  unavailable: 0,
  notAttempted: 1,
  attempted: 2,
  accepted: 3,
  rejected: 4,
};
const stateCodes = {
  handshakeReady: 0,
  handshakeConfirmed: 1,
  failed: 2,
};
const wasmOptionFlags = {
  zeroRtt: 1 << 6,
};
const flowControlFrameTypes = new Set([
  "MAX_DATA",
  "MAX_STREAM_DATA",
  "DATA_BLOCKED",
  "STREAM_DATA_BLOCKED",
]);
const pingPongPayloadBytes = 360;

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

function wasmI64ToNumber(value, label) {
  const number = typeof value === "bigint" ? Number(value) : Number(value);
  if (!Number.isSafeInteger(number)) {
    throw new Error(`${label} is outside JavaScript's safe integer range`);
  }
  return number;
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

function makeState() {
  return {
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
    receivedDatagrams: [],
    flowControlFrames: new Set(),
    resumptionState: null,
    zeroRttStatuses: [],
    serverStreamBeforeConfirmed: false,
  };
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
      if (label === "server" && !state.serverConfirmed) {
        state.serverStreamBeforeConfirmed = true;
      }
      state.received.push({
        endpoint: label,
        streamId: event.streamId,
        fin: event.fin,
        payloadLength: event.payload.length,
        text: new TextDecoder().decode(event.payload),
      });
    }
    if (event.type === eventTypes.receiveDatagram) {
      state.receivedDatagrams.push({
        endpoint: label,
        payloadLength: event.payload.length,
        text: new TextDecoder().decode(event.payload),
      });
    }
    if (event.type === eventTypes.zeroRttStatus) {
      state.zeroRttStatuses.push({
        endpoint: label,
        code: event.code,
        connection: event.connection,
      });
    }
    if (event.type === eventTypes.resumptionStateAvailable) {
      state.resumptionState = event.payload;
    }
  }
}

function relay(from, to, routeHandle, now, state) {
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
    for (const inspection of inspections) {
      debugLog(
        `inspection endpoint=${from} datagram=${datagram.inspectionDatagramId} frames=${(inspection.frames ?? [])
          .map((frame) => frame.type)
          .join(",")}`,
      );
      for (const frame of inspection.frames ?? []) {
        if (flowControlFrameTypes.has(frame.type)) {
          state.flowControlFrames.add(frame.type);
        }
      }
    }
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
  moved += relay(client, server, 7n, now, state);
  moved += relay(server, client, 1n, now, state);
  drainEvents(client, "client", state);
  drainEvents(server, "server", state);
  return moved;
}

const encoder = new TextEncoder();
const decoder = new TextDecoder();

function pingPongPayload(sender, sequence) {
  const prefix = `${sender} ping-pong ${sequence} `;
  const fill = "flow-control-window ";
  let text = prefix;
  while (encoder.encode(text).length < pingPongPayloadBytes) {
    text += fill;
  }
  return encoder.encode(text).slice(0, pingPongPayloadBytes);
}

function sendStream(endpoint, now, connection, streamId, payload, label) {
  withBytes(payload, (pointer, length) => {
    checked(
      label,
      coquic_wasm_endpoint_send_stream(endpoint, now, connection, streamId, pointer, length, 0),
    );
  });
}

function sendDatagram(endpoint, now, connection, payload, label) {
  withBytes(payload, (pointer, length) => {
    checked(
      label,
      coquic_wasm_endpoint_send_datagram(endpoint, now, connection, pointer, length),
    );
  });
}

function createEndpoint(role, flags = 0) {
  return flags === 0
    ? coquic_wasm_endpoint_create(role, 0, 0, 0, 0)
    : coquic_wasm_endpoint_create_with_options(role, 0, 0, 0, 0, flags);
}

function createEndpointPair(flags = 0) {
  const client = createEndpoint(0, flags);
  const server = createEndpoint(1, flags);
  debugLog(`endpoints client=${client} server=${server} flags=${flags}`);
  if (client === 0 || server === 0) {
    throw new Error(`endpoint creation failed client=${client} server=${server}`);
  }
  return { client, server };
}

function openConnection(endpoint, now, flags = 0, resumptionState = null) {
  if (resumptionState) {
    return withBytes(resumptionState, (pointer, length) =>
      coquic_wasm_endpoint_open_connection_with_resumption(
        endpoint,
        now,
        0,
        0,
        0,
        0,
        1n,
        flags,
        pointer,
        length,
      ),
    );
  }
  return flags === 0
    ? coquic_wasm_endpoint_open_connection(endpoint, now, 0, 0, 0, 0, 1n)
    : coquic_wasm_endpoint_open_connection_with_options(endpoint, now, 0, 0, 0, 0, 1n, flags);
}

function receivedBytes(state, endpoint) {
  return state.received
    .filter((event) => event.endpoint === endpoint)
    .reduce((sum, event) => sum + event.payloadLength, 0);
}

function receivedText(state, endpoint) {
  return state.received
    .filter((event) => event.endpoint === endpoint)
    .map((event) => event.text)
    .join("");
}

function receivedDatagramText(state, endpoint) {
  return state.receivedDatagrams
    .filter((event) => event.endpoint === endpoint)
    .map((event) => event.text)
    .join("");
}

function fireDueTimers(client, server, now) {
  const clientWake = wasmI64ToNumber(coquic_wasm_endpoint_next_wakeup_ms(client), "client wakeup");
  const serverWake = wasmI64ToNumber(coquic_wasm_endpoint_next_wakeup_ms(server), "server wakeup");
  if (clientWake >= 0 && BigInt(clientWake) <= now) {
    checked("client timer", coquic_wasm_endpoint_timer_expired(client, now));
  }
  if (serverWake >= 0 && BigInt(serverWake) <= now) {
    checked("server timer", coquic_wasm_endpoint_timer_expired(server, now));
  }
}

function pumpUntil(client, server, state, now, predicate, label, maxSteps = 128) {
  for (let step = 0; step < maxSteps && !predicate(); step += 1) {
    now += 1n;
    const moved = pump(client, server, state, now);
    debugLog(`${label} step=${step} moved=${moved} state=${jsonState(state)}`);
    if (moved === 0) {
      fireDueTimers(client, server, now);
    }
  }
  if (!predicate()) {
    throw new Error(`${label} did not complete: ${jsonState(state)}`);
  }
  return now;
}

function driveHandshake(
  client,
  server,
  state,
  now,
  { flags = 0, resumptionState = null, afterOpen = null } = {},
) {
  const emptyClientDiagnostics = endpointDiagnostics(client);
  if (emptyClientDiagnostics.role !== "client" || emptyClientDiagnostics.connection_count !== 0) {
    throw new Error(`unexpected empty client diagnostics ${jsonState(emptyClientDiagnostics)}`);
  }

  const connection = openConnection(client, now, flags, resumptionState);
  debugLog(`open connection=${connection}`);
  if (connection <= 0) {
    throw new Error(`open connection failed with ${connection}`);
  }
  state.clientConnection = BigInt(connection);
  const openedClientDiagnostics = endpointDiagnostics(client);
  if (openedClientDiagnostics.connection_count !== 1) {
    throw new Error(`client diagnostics did not expose opened connection ${jsonState(openedClientDiagnostics)}`);
  }
  if (afterOpen) {
    afterOpen(now, state);
  }

  for (let step = 0; step < 96 && !(state.clientConfirmed && state.serverConfirmed); step += 1) {
    now += 1n;
    const moved = pump(client, server, state, now);
    const clientWake = wasmI64ToNumber(coquic_wasm_endpoint_next_wakeup_ms(client), "client wakeup");
    const serverWake = wasmI64ToNumber(coquic_wasm_endpoint_next_wakeup_ms(server), "server wakeup");
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

  if (!state.clientConfirmed || !state.serverConfirmed) {
    throw new Error(`handshake did not confirm: ${jsonState(state)}`);
  }
  if (state.serverConnection === 0n) {
    throw new Error("server did not emit an accepted connection handle");
  }
  return now;
}

function runTransferSmoke() {
  const { client, server } = createEndpointPair();
  const state = makeState();
  try {
    let now = driveHandshake(client, server, state, 0n);

    const expectedByEndpoint = {
      client: "",
      server: "",
    };
    const appendExpected = (endpointName, text) => {
      if (endpointName === "client") {
        expectedByEndpoint.client += text;
        return expectedByEndpoint.client.length;
      }
      expectedByEndpoint.server += text;
      return expectedByEndpoint.server.length;
    };

    for (let sequence = 1; sequence <= 4; sequence += 1) {
      const sender = sequence % 2 === 1 ? "client" : "server";
      const receiver = sender === "client" ? "server" : "client";
      const endpoint = sender === "client" ? client : server;
      const connectionHandle =
        sender === "client" ? state.clientConnection : state.serverConnection;
      const payload = pingPongPayload(sender, sequence);

      const expectedLength = appendExpected(receiver, decoder.decode(payload));
      sendStream(
        endpoint,
        now,
        connectionHandle,
        0n,
        payload,
        `${sender} send ping-pong ${sequence}`,
      );
      now = pumpUntil(
        client,
        server,
        state,
        now,
        () => receivedBytes(state, receiver) >= expectedLength,
        `${sender} ping-pong ${sequence}`,
      );
    }

    if (receivedText(state, "server") !== expectedByEndpoint.server) {
      throw new Error(`unexpected server receive event ${jsonState(state.received)}`);
    }
    if (receivedText(state, "client") !== expectedByEndpoint.client) {
      throw new Error(`unexpected receive event ${jsonState(state.received)}`);
    }
    if (state.packetInspections === 0 || state.inspectedFrames === 0) {
      throw new Error(`packet inspection did not produce frame records: ${jsonState(state)}`);
    }
    if (!state.flowControlFrames.has("MAX_DATA") || !state.flowControlFrames.has("MAX_STREAM_DATA")) {
      throw new Error(`flow-control frames were not inspected: ${jsonState([...state.flowControlFrames])}`);
    }
    const serverDiagnostics = endpointDiagnostics(server);
    if (serverDiagnostics.connection_count !== 1 || serverDiagnostics.connections[0]?.active_streams === undefined) {
      throw new Error(`server diagnostics missing connection internals ${jsonState(serverDiagnostics)}`);
    }
  } finally {
    coquic_wasm_endpoint_destroy(client);
    coquic_wasm_endpoint_destroy(server);
  }
}

function collectResumptionState() {
  const { client, server } = createEndpointPair(wasmOptionFlags.zeroRtt);
  const state = makeState();
  try {
    driveHandshake(client, server, state, 0n, { flags: wasmOptionFlags.zeroRtt });
    if (!state.resumptionState || state.resumptionState.length === 0) {
      throw new Error(`resumption state was not emitted: ${jsonState(state)}`);
    }
    return state.resumptionState;
  } finally {
    coquic_wasm_endpoint_destroy(client);
    coquic_wasm_endpoint_destroy(server);
  }
}

function runResumptionZeroRttSmoke() {
  const resumptionState = collectResumptionState();
  const { client, server } = createEndpointPair(wasmOptionFlags.zeroRtt);
  const state = makeState();
  const earlyPayload = encoder.encode("client zero-rtt smoke early data");
  const expectedEarlyText = decoder.decode(earlyPayload);
  try {
    const now = driveHandshake(client, server, state, 100n, {
      flags: wasmOptionFlags.zeroRtt,
      resumptionState,
      afterOpen: (currentNow) => {
        sendStream(client, currentNow, state.clientConnection, 0n, earlyPayload, "client zero-rtt send");
      },
    });
    pumpUntil(
      client,
      server,
      state,
      now,
      () => receivedText(state, "server").includes(expectedEarlyText),
      "zero-rtt early data receive",
    );
    if (!receivedText(state, "server").includes(expectedEarlyText)) {
      throw new Error(`server did not receive zero-rtt stream data: ${jsonState(state.received)}`);
    }
    if (!state.serverStreamBeforeConfirmed) {
      throw new Error(`server stream data did not arrive before handshake confirmation: ${jsonState(state)}`);
    }
    if (state.zeroRttStatuses.some((event) =>
      event.code === zeroRttStatusCodes.unavailable || event.code === zeroRttStatusCodes.rejected
    )) {
      throw new Error(`zero-rtt was reported unavailable or rejected: ${jsonState(state.zeroRttStatuses)}`);
    }
  } finally {
    coquic_wasm_endpoint_destroy(client);
    coquic_wasm_endpoint_destroy(server);
  }
}

function runDatagramSmoke() {
  if (typeof coquic_wasm_endpoint_send_datagram !== "function") {
    throw new Error("missing coquic_wasm_endpoint_send_datagram export");
  }
  const { client, server } = createEndpointPair();
  const state = makeState();
  const clientPayload = encoder.encode("client QUIC DATAGRAM smoke payload");
  const serverPayload = encoder.encode("server QUIC DATAGRAM smoke payload");
  try {
    let now = driveHandshake(client, server, state, 0n);

    sendDatagram(client, now, state.clientConnection, clientPayload, "client send datagram");
    now = pumpUntil(
      client,
      server,
      state,
      now,
      () => receivedDatagramText(state, "server").includes(decoder.decode(clientPayload)),
      "client datagram receive",
    );

    sendDatagram(server, now, state.serverConnection, serverPayload, "server send datagram");
    pumpUntil(
      client,
      server,
      state,
      now,
      () => receivedDatagramText(state, "client").includes(decoder.decode(serverPayload)),
      "server datagram receive",
    );
  } finally {
    coquic_wasm_endpoint_destroy(client);
    coquic_wasm_endpoint_destroy(server);
  }
}

runTransferSmoke();
runResumptionZeroRttSmoke();
runDatagramSmoke();
console.log("wasm-quic smoke ok");

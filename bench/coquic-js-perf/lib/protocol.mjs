import { Direction, Mode } from "./config.mjs";

export const PROTOCOL_VERSION_LEGACY = 1;
export const PROTOCOL_VERSION_MILLISECONDS = 2;
export const PROTOCOL_VERSION = 3;
export const CONTROL_STREAM_ID = 0;
export const FIRST_DATA_STREAM_ID = 4;

const MESSAGE_SESSION_START = 1;
const MESSAGE_SESSION_READY = 2;
const MESSAGE_SESSION_ERROR = 3;
const MESSAGE_SESSION_COMPLETE = 4;

const OPTIONAL_TOTAL_BYTES_FLAG = 0x01;
const OPTIONAL_REQUESTS_FLAG = 0x02;

export class SessionStart {
  constructor({
    protocolVersion = PROTOCOL_VERSION,
    mode = Mode.BULK,
    direction = Direction.DOWNLOAD,
    requestBytes = 0,
    responseBytes = 0,
    totalBytes = null,
    requests = null,
    warmup = 0.0,
    duration = 0.0,
    streams = 1,
    connections = 1,
    requestsInFlight = 1,
  } = {}) {
    this.protocolVersion = protocolVersion;
    this.mode = mode;
    this.direction = direction;
    this.requestBytes = requestBytes;
    this.responseBytes = responseBytes;
    this.totalBytes = totalBytes;
    this.requests = requests;
    this.warmup = warmup;
    this.duration = duration;
    this.streams = streams;
    this.connections = connections;
    this.requestsInFlight = requestsInFlight;
  }
}

export class SessionReady {
  constructor(protocolVersion) {
    this.protocolVersion = protocolVersion;
  }
}

export class SessionError {
  constructor(reason) {
    this.reason = reason;
  }
}

export class SessionComplete {
  constructor({ bytesSent = 0, bytesReceived = 0, requestsCompleted = 0 } = {}) {
    this.bytesSent = bytesSent;
    this.bytesReceived = bytesReceived;
    this.requestsCompleted = requestsCompleted;
  }
}

export function encodeControlMessage(message) {
  const payload = [];
  let messageType;
  if (message instanceof SessionStart) {
    messageType = MESSAGE_SESSION_START;
    appendU32(payload, message.protocolVersion);
    appendU8(payload, modeToU8(message.mode));
    appendU8(payload, directionToU8(message.direction));
    appendU64(payload, message.requestBytes);
    appendU64(payload, message.responseBytes);
    if (message.protocolVersion !== PROTOCOL_VERSION_LEGACY) {
      appendU8(payload, sessionStartOptionalFlags(message));
    }
    appendU64(payload, message.totalBytes ?? 0);
    appendU64(payload, message.requests ?? 0);
    if (
      message.protocolVersion === PROTOCOL_VERSION_LEGACY ||
      message.protocolVersion === PROTOCOL_VERSION_MILLISECONDS
    ) {
      appendU64(payload, durationMs(message.warmup));
      appendU64(payload, durationMs(message.duration));
    } else {
      appendU64(payload, durationUs(message.warmup));
      appendU64(payload, durationUs(message.duration));
    }
    appendU64(payload, message.streams);
    appendU64(payload, message.connections);
    appendU64(payload, message.requestsInFlight);
  } else if (message instanceof SessionReady) {
    messageType = MESSAGE_SESSION_READY;
    appendU32(payload, message.protocolVersion);
  } else if (message instanceof SessionError) {
    messageType = MESSAGE_SESSION_ERROR;
    const data = Buffer.from(message.reason);
    appendU32(payload, data.length);
    payload.push(...data);
  } else {
    messageType = MESSAGE_SESSION_COMPLETE;
    appendU64(payload, message.bytesSent);
    appendU64(payload, message.bytesReceived);
    appendU64(payload, message.requestsCompleted);
  }

  const out = [];
  appendU8(out, messageType);
  appendU32(out, payload.length);
  out.push(...payload);
  return Buffer.from(out);
}

export function decodeControlMessage(data) {
  data = Buffer.from(data);
  if (data.length < 5) {
    return null;
  }
  const messageType = data[0];
  const payloadSize = data.readUInt32BE(1);
  const payload = data.subarray(5);
  if (payload.length !== payloadSize) {
    return null;
  }
  const reader = new Reader(payload);
  try {
    if (messageType === MESSAGE_SESSION_START) {
      return decodeSessionStart(reader);
    }
    if (messageType === MESSAGE_SESSION_READY) {
      const protocolVersion = reader.takeU32();
      return reader.empty ? new SessionReady(protocolVersion) : null;
    }
    if (messageType === MESSAGE_SESSION_ERROR) {
      const reason = reader.takeString();
      return reader.empty ? new SessionError(reason) : null;
    }
    if (messageType === MESSAGE_SESSION_COMPLETE) {
      const bytesSent = reader.takeU64();
      const bytesReceived = reader.takeU64();
      const requestsCompleted = reader.takeU64();
      return reader.empty
        ? new SessionComplete({ bytesSent, bytesReceived, requestsCompleted })
        : null;
    }
  } catch {
    return null;
  }
  return null;
}

export function takeControlMessage(buffer) {
  if (buffer.length < 5) {
    return null;
  }
  const view = Buffer.from(buffer);
  const payloadSize = view.readUInt32BE(1);
  const frameSize = 5 + payloadSize;
  if (buffer.length < frameSize) {
    return null;
  }
  const frame = Buffer.from(buffer.slice(0, frameSize));
  buffer.splice(0, frameSize);
  return decodeControlMessage(frame);
}

export function nextClientStreamId(current) {
  return current === 0 ? FIRST_DATA_STREAM_ID : current + 4;
}

function decodeSessionStart(reader) {
  const protocolVersion = reader.takeU32();
  const mode = parseMode(reader.takeU8());
  const direction = parseDirection(reader.takeU8());
  if (mode == null || direction == null) {
    return null;
  }
  const requestBytes = reader.takeU64();
  const responseBytes = reader.takeU64();

  let optionalFlags;
  if (
    protocolVersion === PROTOCOL_VERSION ||
    protocolVersion === PROTOCOL_VERSION_MILLISECONDS
  ) {
    optionalFlags = reader.takeU8();
  } else if (protocolVersion === PROTOCOL_VERSION_LEGACY) {
    optionalFlags = 0;
  } else {
    return null;
  }

  const totalBytesRaw = reader.takeU64();
  const requestsRaw = reader.takeU64();
  const warmupRaw = reader.takeU64();
  const durationRaw = reader.takeU64();
  const streams = reader.takeU64();
  const connections = reader.takeU64();
  const requestsInFlight = reader.takeU64();
  if (!reader.empty) {
    return null;
  }

  const totalBytes =
    protocolVersion === PROTOCOL_VERSION_LEGACY
      ? totalBytesRaw || null
      : optionalFlags & OPTIONAL_TOTAL_BYTES_FLAG
        ? totalBytesRaw
        : null;
  const requests =
    protocolVersion === PROTOCOL_VERSION_LEGACY
      ? requestsRaw || null
      : optionalFlags & OPTIONAL_REQUESTS_FLAG
        ? requestsRaw
        : null;
  const warmup =
    protocolVersion === PROTOCOL_VERSION_LEGACY ||
    protocolVersion === PROTOCOL_VERSION_MILLISECONDS
      ? warmupRaw / 1000.0
      : warmupRaw / 1_000_000.0;
  const duration =
    protocolVersion === PROTOCOL_VERSION_LEGACY ||
    protocolVersion === PROTOCOL_VERSION_MILLISECONDS
      ? durationRaw / 1000.0
      : durationRaw / 1_000_000.0;

  return new SessionStart({
    protocolVersion,
    mode,
    direction,
    requestBytes,
    responseBytes,
    totalBytes,
    requests,
    warmup,
    duration,
    streams,
    connections,
    requestsInFlight,
  });
}

class Reader {
  constructor(data) {
    this.data = data;
    this.offset = 0;
  }

  get empty() {
    return this.offset === this.data.length;
  }

  takeU8() {
    if (this.offset >= this.data.length) {
      throw new Error("short input");
    }
    return this.data[this.offset++];
  }

  takeU32() {
    if (this.data.length - this.offset < 4) {
      throw new Error("short input");
    }
    const value = this.data.readUInt32BE(this.offset);
    this.offset += 4;
    return value;
  }

  takeU64() {
    if (this.data.length - this.offset < 8) {
      throw new Error("short input");
    }
    const value = Number(this.data.readBigUInt64BE(this.offset));
    this.offset += 8;
    return value;
  }

  takeString() {
    const size = this.takeU32();
    if (this.data.length - this.offset < size) {
      throw new Error("short input");
    }
    const value = this.data.subarray(this.offset, this.offset + size).toString();
    this.offset += size;
    return value;
  }
}

function appendU8(out, value) {
  out.push(value & 0xff);
}

function appendU32(out, value) {
  const buffer = Buffer.alloc(4);
  buffer.writeUInt32BE(value >>> 0);
  out.push(...buffer);
}

function appendU64(out, value) {
  const buffer = Buffer.alloc(8);
  buffer.writeBigUInt64BE(BigInt(value));
  out.push(...buffer);
}

function modeToU8(mode) {
  return { [Mode.BULK]: 0, [Mode.RR]: 1, [Mode.CRR]: 2 }[mode];
}

function parseMode(value) {
  return { 0: Mode.BULK, 1: Mode.RR, 2: Mode.CRR }[value] ?? null;
}

function directionToU8(direction) {
  return { [Direction.UPLOAD]: 0, [Direction.DOWNLOAD]: 1 }[direction];
}

function parseDirection(value) {
  return { 0: Direction.UPLOAD, 1: Direction.DOWNLOAD }[value] ?? null;
}

function sessionStartOptionalFlags(start) {
  let flags = 0;
  if (start.totalBytes !== null) {
    flags |= OPTIONAL_TOTAL_BYTES_FLAG;
  }
  if (start.requests !== null) {
    flags |= OPTIONAL_REQUESTS_FLAG;
  }
  return flags;
}

function durationUs(seconds) {
  return Math.min(Math.trunc(seconds * 1_000_000), Number.MAX_SAFE_INTEGER);
}

function durationMs(seconds) {
  return Math.min(Math.trunc(seconds * 1000), Number.MAX_SAFE_INTEGER);
}

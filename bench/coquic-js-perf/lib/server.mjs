import { Endpoint, Lifecycle, StateChange } from "@coquic/coquic";

import { Direction, Mode, serverEndpointConfig } from "./config.mjs";
import { PerfError } from "./error.mjs";
import { timeUsToNumber, UdpRuntime } from "./io.mjs";
import { newRunSummary } from "./metrics.mjs";
import {
  CONTROL_STREAM_ID,
  PROTOCOL_VERSION,
  PROTOCOL_VERSION_LEGACY,
  SessionComplete,
  SessionError,
  SessionReady,
  SessionStart,
  decodeControlMessage,
  encodeControlMessage,
} from "./protocol.mjs";

const IDLE_TIMEOUT = 1.0;

class Session {
  constructor() {
    this.controlBytes = [];
    this.start = null;
    this.completeSent = false;
    this.bytesSent = 0;
    this.bytesReceived = 0;
    this.requestsCompleted = 0;
    this.persistentPending = new Map();
  }
}

class SendResponseCommand {
  constructor(connection, streamId, bytes, fin = true) {
    this.connection = connection;
    this.streamId = streamId;
    this.bytes = bytes;
    this.fin = fin;
  }
}

class SendControlCommand {
  constructor(connection, message) {
    this.connection = connection;
    this.message = message;
  }
}

export async function runServer(config) {
  const endpoint = new Endpoint(serverEndpointConfig(config));
  const io = await UdpRuntime.server(config.host, config.port);
  try {
    const server = new Server(endpoint, io);
    await server.run();
    return newRunSummary(config);
  } finally {
    io.close();
    endpoint.close();
  }
}

class Server {
  constructor(endpoint, io) {
    this.endpoint = endpoint;
    this.io = io;
    this.sessions = new Map();
    this.payloadCache = new Map();
    this.completedCrrSessions = new Set();
    this.acceptedSession = false;
    this.completedSessionSeen = false;
  }

  async run() {
    while (true) {
      await this.handleDueTimer();
      if (this.shouldExitOnSessionComplete() || this.shouldExitOnIdleEmpty()) {
        return;
      }

      const event = await this.io.wait(this.endpoint.nextWakeup(), IDLE_TIMEOUT);
      if (event.kind === "datagram") {
        const now = this.io.nowUs();
        const result = this.endpoint.receiveDatagram(this.io.inboundDatagram(event.datagram), now);
        await this.handleResult(result, now);
      } else if (event.kind === "timer") {
        const now = this.io.nowUs();
        const result = this.endpoint.timerExpired(now);
        await this.handleResult(result, now);
      } else {
        await this.io.flushSends();
        if (this.shouldExitOnIdleEmpty() || this.shouldExitOnSessionComplete()) {
          return;
        }
      }
    }
  }

  async handleDueTimer() {
    while (true) {
      const wakeup = timeUsToNumber(this.endpoint.nextWakeup());
      if (wakeup == null) {
        return;
      }
      const now = this.io.nowUs();
      if (wakeup > now) {
        return;
      }
      const result = this.endpoint.timerExpired(now);
      await this.handleResult(result, now);
    }
  }

  async handleResult(result, now) {
    const pending = [result];
    while (pending.length > 0) {
      const current = pending.pop();
      const commands = this.collectResultCommands(current);
      for (const command of commands) {
        pending.push(this.executeCommand(command, now));
      }
    }
    await this.io.flushSends();
  }

  collectResultCommands(result) {
    if (result.localError != null) {
      throw new PerfError(`server local error: ${JSON.stringify(result.localError)}`);
    }

    const commands = [];
    for (const effect of this.io.collectResultEffects(result)) {
      if (effect.kind === "connection_lifecycle_event") {
        if (effect.event === Lifecycle.ACCEPTED) {
          this.acceptedSession = true;
          this.sessions.set(Number(effect.connection), new Session());
        } else if (effect.event === Lifecycle.CLOSED) {
          const connection = Number(effect.connection);
          const session = this.sessions.get(connection);
          if (
            session?.start != null &&
            session.start.mode === Mode.CRR &&
            session.requestsCompleted > 0
          ) {
            this.completedCrrSessions.add(connection);
          }
          this.sessions.delete(connection);
        }
      } else if (
        effect.kind === "state_event" &&
        effect.change === StateChange.FAILED &&
        !this.tolerateFailedState(Number(effect.connection))
      ) {
        throw new PerfError(`server core state failed connection=${effect.connection}`);
      } else if (effect.kind === "receive_stream_data") {
        commands.push(
          ...this.handleStreamData(
            Number(effect.connection),
            Number(effect.streamId),
            effect.bytes,
            effect.fin,
          ),
        );
      }
    }
    return commands;
  }

  handleStreamData(connection, streamId, data, fin) {
    if (streamId === CONTROL_STREAM_ID) {
      return this.handleControlStreamData(connection, data, fin);
    }

    const session = this.sessions.get(connection);
    if (session == null || session.start == null) {
      return [];
    }

    this.recordStreamData(session, data, fin);
    if (session.start.mode === Mode.PERSISTENT_RR) {
      return this.handlePersistentRrData(connection, streamId, session, data.length, fin);
    }
    if (!fin) {
      return [];
    }
    if (session.start.mode === Mode.BULK) {
      return this.handleBulkStreamFin(connection, streamId, session);
    }
    if (session.start.mode === Mode.RR || session.start.mode === Mode.CRR) {
      return this.handleRequestResponseFin(connection, streamId, session);
    }
    return [];
  }

  handleControlStreamData(connection, data, fin) {
    const session = this.sessions.get(connection);
    if (session == null) {
      throw new PerfError("control stream for unknown session");
    }
    session.controlBytes.push(...data);
    if (!fin) {
      return [];
    }

    const decoded = decodeControlMessage(Buffer.from(session.controlBytes));
    session.controlBytes = [];
    if (!(decoded instanceof SessionStart)) {
      return [new SendControlCommand(connection, new SessionError("expected session_start"))];
    }

    const reason = validateSessionStart(decoded);
    if (reason != null) {
      return [new SendControlCommand(connection, new SessionError(reason))];
    }

    session.start = decoded;
    return [new SendControlCommand(connection, new SessionReady(PROTOCOL_VERSION))];
  }

  recordStreamData(session, data, fin) {
    session.bytesReceived += data.length;
    if (fin && session.start?.mode !== Mode.PERSISTENT_RR) {
      session.requestsCompleted += 1;
    }
  }

  handlePersistentRrData(connection, streamId, session, byteCount, fin) {
    const start = session.start;
    let pending = (session.persistentPending.get(streamId) ?? 0) + byteCount;
    const commands = [];
    while (pending >= start.requestBytes) {
      commands.push(new SendResponseCommand(connection, streamId, start.responseBytes, false));
      session.bytesSent += start.responseBytes;
      session.requestsCompleted += 1;
      pending -= start.requestBytes;
      if (start.requests != null && session.requestsCompleted >= start.requests) {
        commands.push(...this.completeSession(connection));
        break;
      }
    }
    if (fin) {
      session.persistentPending.delete(streamId);
    } else {
      session.persistentPending.set(streamId, pending);
    }
    return commands;
  }

  handleBulkStreamFin(connection, streamId, session) {
    const start = session.start;
    if (start.direction === Direction.DOWNLOAD) {
      return this.handleBulkDownloadFin(connection, streamId, session);
    }
    if (start.totalBytes != null && session.requestsCompleted >= start.streams) {
      return this.completeSession(connection);
    }
    return [];
  }

  handleBulkDownloadFin(connection, streamId, session) {
    const start = session.start;
    let target = start.responseBytes;
    const commands = [];
    if (start.totalBytes != null) {
      const streamIndex = Math.max(session.requestsCompleted - 1, 0);
      const perStream = Math.trunc(start.totalBytes / start.streams);
      const remainder = start.totalBytes % start.streams;
      target = perStream + (streamIndex < remainder ? 1 : 0);
    }
    commands.push(new SendResponseCommand(connection, streamId, target));
    session.bytesSent += target;
    if (start.totalBytes != null && session.requestsCompleted >= start.streams) {
      commands.push(...this.completeSession(connection));
    }
    return commands;
  }

  handleRequestResponseFin(connection, streamId, session) {
    const start = session.start;
    const commands = [new SendResponseCommand(connection, streamId, start.responseBytes)];
    session.bytesSent += start.responseBytes;
    if (
      start.mode === Mode.RR &&
      start.requests != null &&
      session.requestsCompleted >= start.requests
    ) {
      commands.push(...this.completeSession(connection));
    }
    return commands;
  }

  completeSession(connection) {
    const complete = this.makeCompleteCommand(connection);
    return complete == null ? [] : [complete];
  }

  executeCommand(command, now) {
    if (command instanceof SendResponseCommand) {
      return this.endpoint
        .connection(command.connection)
        .stream(command.streamId)
        .send(this.cachedPayload(command.bytes), command.fin, now);
    }

    const fin =
      command.message instanceof SessionError || command.message instanceof SessionComplete;
    return this.endpoint
      .connection(command.connection)
      .stream(CONTROL_STREAM_ID)
      .send(encodeControlMessage(command.message), fin, now);
  }

  cachedPayload(size) {
    let payload = this.payloadCache.get(size);
    if (payload == null) {
      payload = makePayload(size);
      this.payloadCache.set(size, payload);
    }
    return payload;
  }

  makeCompleteCommand(connection) {
    const session = this.sessions.get(connection);
    if (session == null || session.completeSent) {
      return null;
    }
    session.completeSent = true;
    this.completedSessionSeen = true;
    return new SendControlCommand(
      connection,
      new SessionComplete({
        bytesSent: session.bytesSent,
        bytesReceived: session.bytesReceived,
        requestsCompleted: session.requestsCompleted,
      }),
    );
  }

  shouldExitOnIdleEmpty() {
    return this.acceptedSession && this.sessions.size === 0 && envFlagEnabled("COQUIC_PERF_SERVER_EXIT_ON_IDLE_EMPTY");
  }

  shouldExitOnSessionComplete() {
    return (
      this.acceptedSession &&
      this.completedSessionSeen &&
      envFlagEnabled("COQUIC_PERF_SERVER_EXIT_ON_SESSION_COMPLETE") &&
      Array.from(this.sessions.values()).every((session) => session.completeSent) &&
      !this.endpoint.hasSendContinuationPending() &&
      !this.endpoint.hasPendingStreamSend()
    );
  }

  tolerateFailedState(connection) {
    const session = this.sessions.get(connection);
    return (
      this.completedCrrSessions.has(connection) ||
      (session?.start != null && session.start.mode === Mode.CRR && session.requestsCompleted > 0)
    );
  }
}

function validateSessionStart(start) {
  if (![PROTOCOL_VERSION, PROTOCOL_VERSION_LEGACY].includes(start.protocolVersion)) {
    return "unsupported protocol version";
  }
  if (start.streams === 0) {
    return "streams must be greater than zero";
  }
  if (start.connections === 0) {
    return "connections must be greater than zero";
  }
  if (start.requestsInFlight === 0) {
    return "requests_in_flight must be greater than zero";
  }
  if (
    start.mode === Mode.PERSISTENT_RR &&
    (start.requestBytes === 0 || start.responseBytes === 0)
  ) {
    return "persistent-rr requires nonzero request and response bytes";
  }
  return null;
}

function makePayload(size) {
  return Buffer.alloc(size, 0x5a);
}

function envFlagEnabled(name) {
  const value = process.env[name];
  return value != null && value !== "" && value !== "0";
}

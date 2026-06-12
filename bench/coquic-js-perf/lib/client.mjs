import { ClientConfig, Endpoint, Lifecycle, StateChange } from "@coquic/coquic";

import { Direction, Mode, clientEndpointConfig } from "./config.mjs";
import { PerfError } from "./error.mjs";
import { timeUsToNumber, UdpRuntime } from "./io.mjs";
import {
  durationMillis,
  finalizeSummary,
  newRunSummary,
  newServerCounters,
  resetMeasurement,
} from "./metrics.mjs";
import {
  CONTROL_STREAM_ID,
  FIRST_DATA_STREAM_ID,
  PROTOCOL_VERSION,
  SessionComplete,
  SessionError,
  SessionReady,
  SessionStart,
  encodeControlMessage,
  nextClientStreamId,
  takeControlMessage,
} from "./protocol.mjs";

const IDLE_TIMEOUT = 5.0;
const DRAIN_TIMEOUT = 2.0;

const BenchmarkPhase = Object.freeze({
  WARMUP: "warmup",
  MEASURE: "measure",
  DRAIN: "drain",
});

class OutstandingRequest {
  constructor(startedAt, countsTowardMeasurement) {
    this.startedAt = startedAt;
    this.countsTowardMeasurement = countsTowardMeasurement;
  }
}

class ConnectionState {
  constructor() {
    this.sessionReady = false;
    this.controlComplete = false;
    this.closeRequested = false;
    this.controlBytes = [];
    this.outstandingRequests = new Map();
    this.persistentRequests = [];
    this.activeBulkStreams = new Map();
    this.nextStreamId = FIRST_DATA_STREAM_ID;
    this.persistentStreamId = null;
    this.persistentFinSent = false;
    this.persistentPendingRead = 0;
    this.requestLimit = null;
    this.requestsStarted = 0;
    this.serverCompleteCounted = false;
  }
}

export const testHooks = Object.freeze({
  BenchmarkPhase,
  ConnectionState,
  OutstandingRequest,
  durationUs,
});

class OpenConnectionCommand {}

class SendStreamCommand {
  constructor(connection, streamId, bytes, fin) {
    this.connection = connection;
    this.streamId = streamId;
    this.bytes = bytes;
    this.fin = fin;
  }
}

class CloseCommand {
  constructor(connection, reason) {
    this.connection = connection;
    this.reason = reason;
  }
}

class ResultWork {
  constructor(result) {
    this.result = result;
  }
}

class CommandWork {
  constructor(command) {
    this.command = command;
  }
}

export async function runClient(config) {
  const endpoint = new Endpoint(clientEndpointConfig(config));
  const { io, primaryRoute, primaryIdentity } = await UdpRuntime.client(config.host, config.port);
  try {
    const client = new Client(config, endpoint, io, primaryRoute, primaryIdentity);
    return await client.run();
  } finally {
    io.close();
    endpoint.close();
  }
}

export class Client {
  constructor(config, endpoint, io, primaryRoute, primaryIdentity) {
    this.config = config;
    this.endpoint = endpoint;
    this.io = io;
    this.primaryRoute = primaryRoute;
    this.primaryIdentity = primaryIdentity;
    this.connections = new Map();
    this.closingConnections = new Set();
    this.closedConnections = new Set();
    this.requestsStarted = 0;
    this.crrRequestsOpened = 0;
    this.nextConnectionIndex = 0;
    this.phase = BenchmarkPhase.WARMUP;
    this.runStartedAt = 0;
    this.benchmarkStartedAt = null;
    this.measureStartedAt = 0;
    this.measureDeadline = 0;
    this.drainDeadline = null;
    this.summary = newRunSummary(config);
  }

  async run() {
    const start = this.io.nowUs();
    this.runStartedAt = start;
    this.measureStartedAt = start;
    this.phase = BenchmarkPhase.WARMUP;
    if (!this.timedMode()) {
      this.benchmarkStartedAt = start;
    }

    for (let index = 0; index < this.initialConnectionTarget(); index += 1) {
      const result = this.executeCommand(new OpenConnectionCommand(), start);
      if (result != null) {
        await this.handleResult(result, start);
      }
    }

    while (true) {
      const now = this.io.nowUs();
      await this.advanceBenchmarkPhase(now);

      if (this.runComplete()) {
        await this.io.flushSends();
        if (
          this.timedBulkMode() &&
          this.config.direction === Direction.DOWNLOAD &&
          this.config.responseBytes > 0 &&
          this.summary.bytes_received === 0
        ) {
          throw new PerfError("timed bulk download measured zero bytes");
        }
        this.summary.status = "ok";
        this.summary.elapsed_ms = durationMillis(this.resultElapsedSeconds(now));
        if (this.timedRrMode() || this.timedPersistentRrMode() || this.timedCrrMode()) {
          this.summary.server_counters = {
            bytes_sent: this.summary.bytes_received,
            bytes_received: this.summary.bytes_sent,
            requests_completed: this.summary.requests_completed,
          };
        }
        finalizeSummary(this.summary);
        return this.summary;
      }

      await this.handleDueTimer();
      await this.maybeOpenCrrConnections();
      await this.io.flushSends();

      const event = await this.io.wait(
        this.nextWaitWakeup(this.endpoint.nextWakeup()),
        IDLE_TIMEOUT,
      );
      if (event.kind === "datagram") {
        const eventNow = this.io.nowUs();
        await this.advanceBenchmarkPhase(eventNow);
        const result = this.endpoint.receiveDatagram(
          this.io.inboundDatagram(event.datagram),
          eventNow,
        );
        await this.handleResult(result, eventNow);
      } else if (event.kind === "timer") {
        const eventNow = this.io.nowUs();
        await this.advanceBenchmarkPhase(eventNow);
        await this.handleDueTimer();
      } else if (this.canWaitThroughIdle()) {
        await this.advanceBenchmarkPhase(this.io.nowUs());
      } else {
        throw new PerfError("client timed out waiting for progress");
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
    const pending = [new ResultWork(result)];
    while (pending.length > 0) {
      const work = pending.pop();
      if (work instanceof ResultWork) {
        const commands = this.collectResultCommands(work.result, now);
        for (let index = commands.length - 1; index >= 0; index -= 1) {
          pending.push(new CommandWork(commands[index]));
        }
      } else if (work instanceof CommandWork) {
        const nextResult = this.executeCommand(work.command, now);
        if (nextResult != null) {
          pending.push(new ResultWork(nextResult));
        }
      }
    }
    await this.io.flushSends();
  }

  collectResultCommands(result, now) {
    this.advanceBenchmarkPhaseSync(now);
    if (result.localError != null) {
      this.summary.failure_reason = `client local error: ${JSON.stringify(result.localError)}`;
      throw new PerfError(this.summary.failure_reason);
    }

    const commands = [];
    for (const effect of this.io.collectResultEffects(result)) {
      if (effect.kind === "connection_lifecycle_event") {
        if (effect.event === Lifecycle.CREATED) {
          const connection = Number(effect.connection);
          const connectionIndex = this.connections.size;
          if (!this.connections.has(connection)) {
            const state = new ConnectionState();
            state.requestLimit = requestLimitForConnection(this.config, connectionIndex);
            this.connections.set(connection, state);
          }
        } else if (effect.event === Lifecycle.CLOSED) {
          const connection = Number(effect.connection);
          this.closedConnections.add(connection);
          if (this.config.mode === Mode.CRR) {
            this.connections.delete(connection);
          } else if (this.connections.has(connection)) {
            this.connections.get(connection).controlComplete = true;
          }
        }
      } else if (effect.kind === "state_event") {
        if (
          effect.change === StateChange.FAILED &&
          !this.closingConnections.has(Number(effect.connection))
        ) {
          throw new PerfError(`client core state failed connection=${effect.connection}`);
        }
        if (
          effect.change === StateChange.HANDSHAKE_READY &&
          this.connections.has(Number(effect.connection))
        ) {
          const connection = Number(effect.connection);
          commands.push(
            new SendStreamCommand(
              connection,
              CONTROL_STREAM_ID,
              encodeControlMessage(
                this.makeSessionStart(this.connections.get(connection).requestLimit),
              ),
              true,
            ),
          );
        }
      } else if (effect.kind === "receive_stream_data") {
        commands.push(
          ...this.handleStreamData(
            Number(effect.connection),
            Number(effect.streamId),
            effect.bytes,
            effect.fin,
            now,
          ),
        );
      }
    }
    return commands;
  }

  handleStreamData(connection, streamId, data, fin, now) {
    if (streamId === CONTROL_STREAM_ID) {
      return this.handleControlStreamData(connection, data, fin, now);
    }
    if (this.timedBulkMode()) {
      return this.handleBulkData(connection, streamId, data, fin, now);
    }
    if (this.config.mode === Mode.PERSISTENT_RR) {
      return this.handlePersistentRrData(connection, streamId, data, now);
    }
    if (this.config.mode === Mode.RR || this.config.mode === Mode.CRR) {
      return this.handleRequestResponseData(connection, streamId, data, fin, now);
    }
    this.summary.bytes_received += data.length;
    return [];
  }

  handleControlStreamData(connection, data, fin, now) {
    const state = this.connections.get(connection);
    if (state == null) {
      throw new PerfError("control data for unknown connection");
    }
    state.controlBytes.push(...data);
    const messages = this.takeControlMessages(state);
    const commands = [];
    for (const message of messages) {
      commands.push(...this.handleControlMessage(connection, state, message, now));
    }
    if (fin && state.controlBytes.length > 0) {
      throw new PerfError("incomplete control frame at FIN");
    }
    return commands;
  }

  takeControlMessages(state) {
    const messages = [];
    while (true) {
      const message = takeControlMessage(state.controlBytes);
      if (message == null) {
        return messages;
      }
      messages.push(message);
    }
  }

  handleControlMessage(connection, state, message, now) {
    if (message instanceof SessionReady) {
      state.sessionReady = true;
      this.maybeStartTimedBenchmark(now);
      return this.startWorkForConnection(connection, now);
    }
    if (message instanceof SessionError) {
      state.controlComplete = true;
      throw new PerfError(message.reason);
    }
    if (message instanceof SessionComplete) {
      if (!state.serverCompleteCounted) {
        this.summary.server_counters.bytes_sent += message.bytesSent;
        this.summary.server_counters.bytes_received += message.bytesReceived;
        this.summary.server_counters.requests_completed += message.requestsCompleted;
        state.serverCompleteCounted = true;
      }
      if (this.config.mode === Mode.BULK) {
        this.summary.requests_completed = this.summary.server_counters.requests_completed;
      }
      state.controlComplete = true;
      return [];
    }
    throw new PerfError("client received unexpected session_start");
  }

  handleBulkData(connection, streamId, data, fin, now) {
    const commands = [];
    const state = this.connections.get(connection);
    const counts = state?.activeBulkStreams.get(streamId) ?? false;
    const withinWindow = now >= this.measureStartedAt && now < this.measureDeadline;
    if (this.config.direction === Direction.DOWNLOAD && counts && withinWindow) {
      this.summary.bytes_received += data.length;
    }
    if (!fin) {
      return commands;
    }

    state?.activeBulkStreams.delete(streamId);
    commands.push(...this.maybeStartBulkStreams(connection));
    const current = this.connections.get(connection);
    if (
      this.phase === BenchmarkPhase.DRAIN &&
      current != null &&
      current.activeBulkStreams.size === 0
    ) {
      commands.push(...this.maybeCloseBulkConnection(connection));
    }
    return commands;
  }

  handleRequestResponseData(connection, streamId, data, fin, now) {
    const commands = [];
    const state = this.connections.get(connection);
    const request = state?.outstandingRequests.get(streamId);
    if (request == null) {
      return commands;
    }
    if (request.countsTowardMeasurement) {
      this.summary.bytes_received += data.length;
    }
    if (fin) {
      commands.push(...this.finishRequestResponseStream(connection, streamId, state, request, now));
    }
    return commands;
  }

  handlePersistentRrData(connection, streamId, data, now) {
    const state = this.connections.get(connection);
    if (state == null || state.persistentStreamId !== streamId) {
      return [];
    }
    state.persistentPendingRead += data.length;
    while (
      state.persistentPendingRead >= this.config.responseBytes &&
      state.persistentRequests.length > 0
    ) {
      const request = state.persistentRequests.shift();
      state.persistentPendingRead -= this.config.responseBytes;
      if (request.countsTowardMeasurement) {
        this.summary.bytes_received += this.config.responseBytes;
        this.summary.latency_samples.push((now - request.startedAt) / 1_000_000);
        this.summary.requests_completed += 1;
      }
    }
    if (this.phase === BenchmarkPhase.DRAIN) {
      return state.persistentRequests.length === 0
        ? this.maybeClosePersistentRrConnection(connection)
        : [];
    }
    return this.maybeIssuePersistentRrRequests(connection, now);
  }

  finishRequestResponseStream(connection, streamId, state, request, now) {
    if (request.countsTowardMeasurement) {
      this.summary.latency_samples.push((now - request.startedAt) / 1_000_000);
      this.summary.requests_completed += 1;
    }
    state.outstandingRequests.delete(streamId);
    if (this.config.mode === Mode.RR) {
      if (this.phase === BenchmarkPhase.DRAIN && state.outstandingRequests.size === 0) {
        return this.maybeCloseRrConnection(connection);
      }
      return this.maybeIssueRrRequests(connection, now);
    }
    if (!state.closeRequested) {
      return this.closeConnection(connection, Buffer.from("done"));
    }
    return [];
  }

  executeCommand(command, now) {
    if (command instanceof OpenConnectionCommand) {
      const config = this.makeClientConfig(this.nextConnectionIndex);
      this.nextConnectionIndex += 1;
      config.initialRouteHandle = this.primaryRoute;
      config.addressValidationIdentity = this.primaryIdentity;
      return this.endpoint.connect(config, now).result;
    }
    if (command instanceof SendStreamCommand) {
      if (this.closedConnections.has(command.connection)) {
        return null;
      }
      return this.endpoint
        .connection(command.connection)
        .stream(command.streamId)
        .send(command.bytes, command.fin, now);
    }
    if (this.closedConnections.has(command.connection)) {
      return null;
    }
    this.closingConnections.add(command.connection);
    return this.endpoint.connection(command.connection).close(0, command.reason, now);
  }

  startWorkForConnection(connection, now) {
    return [
      ...this.maybeStartBulkStreams(connection),
      ...this.maybeIssueRrRequests(connection, now),
      ...this.maybeIssuePersistentRrRequests(connection, now),
      ...this.maybeIssueCrrRequest(connection, now),
    ];
  }

  maybeStartBulkStreams(connection) {
    const commands = [];
    if (this.config.mode !== Mode.BULK) {
      return commands;
    }
    const state = this.connections.get(connection);
    if (state == null || !state.sessionReady || state.controlComplete) {
      return commands;
    }

    if (this.timedBulkMode()) {
      if (this.phase === BenchmarkPhase.DRAIN) {
        return commands;
      }
      while (
        state.activeBulkStreams.size < this.config.streams &&
        this.benchmarkAcceptsNewWork()
      ) {
        commands.push(
          ...this.openBulkStream(connection, this.phase === BenchmarkPhase.MEASURE),
        );
      }
      return commands;
    }

    if (state.nextStreamId !== FIRST_DATA_STREAM_ID) {
      return commands;
    }

    const totalBytes = this.config.totalBytes ?? 0;
    const perStream = Math.trunc(totalBytes / this.config.streams);
    const remainder = totalBytes % this.config.streams;
    for (let index = 0; index < this.config.streams; index += 1) {
      const streamId = this.nextStreamId(connection);
      const targetBytes = perStream + (index < remainder ? 1 : 0);
      let payload = Buffer.alloc(0);
      if (this.config.direction === Direction.UPLOAD) {
        this.summary.bytes_sent += targetBytes;
        payload = makePayload(targetBytes);
      }
      commands.push(new SendStreamCommand(connection, streamId, payload, true));
    }
    return commands;
  }

  openBulkStream(connection, countsTowardMeasurement) {
    const streamId = this.nextStreamId(connection);
    const state = this.connections.get(connection);
    if (state == null) {
      throw new PerfError("bulk stream for unknown connection");
    }
    state.activeBulkStreams.set(streamId, countsTowardMeasurement);
    let payload = Buffer.alloc(0);
    if (this.config.direction === Direction.UPLOAD) {
      payload = makePayload(Math.max(this.config.requestBytes, this.config.responseBytes));
      if (countsTowardMeasurement) {
        this.summary.bytes_sent += payload.length;
      }
    }
    return [new SendStreamCommand(connection, streamId, payload, true)];
  }

  maybeIssueRrRequests(connection, now) {
    const commands = [];
    if (this.config.mode !== Mode.RR || !this.benchmarkAcceptsNewWork()) {
      return commands;
    }
    const state = this.connections.get(connection);
    if (state == null || !state.sessionReady || state.controlComplete) {
      return commands;
    }

    while (
      state.outstandingRequests.size < this.config.requestsInFlight &&
      (this.config.requests == null || this.requestsStarted < this.config.requests) &&
      (state.requestLimit == null || state.requestsStarted < state.requestLimit)
    ) {
      commands.push(...this.issueRequest(connection, now));
      this.requestsStarted += 1;
    }
    return commands;
  }

  maybeIssuePersistentRrRequests(connection, now) {
    const commands = [];
    if (this.config.mode !== Mode.PERSISTENT_RR || !this.benchmarkAcceptsNewWork()) {
      return commands;
    }
    const state = this.connections.get(connection);
    if (
      state == null ||
      !state.sessionReady ||
      state.controlComplete ||
      state.closeRequested ||
      state.persistentFinSent
    ) {
      return commands;
    }
    if (state.persistentStreamId == null) {
      state.persistentStreamId = this.nextStreamId(connection);
    }

    while (
      state.persistentRequests.length < this.config.requestsInFlight &&
      (this.config.requests == null || this.requestsStarted < this.config.requests) &&
      (state.requestLimit == null || state.requestsStarted < state.requestLimit)
    ) {
      const counts = this.config.requests != null || this.phase === BenchmarkPhase.MEASURE;
      state.persistentRequests.push(new OutstandingRequest(now, counts));
      state.requestsStarted += 1;
      this.requestsStarted += 1;
      if (counts) {
        this.summary.bytes_sent += this.config.requestBytes;
      }
      commands.push(
        new SendStreamCommand(
          connection,
          state.persistentStreamId,
          makePayload(this.config.requestBytes),
          false,
        ),
      );
    }

    if (
      this.config.requests != null &&
      (state.requestLimit == null || state.requestsStarted >= state.requestLimit)
    ) {
      commands.push(...this.maybeFinishPersistentRrStream(connection));
    }
    return commands;
  }

  maybeIssueCrrRequest(connection, now) {
    const commands = [];
    if (this.config.mode !== Mode.CRR) {
      return commands;
    }
    const state = this.connections.get(connection);
    const canIssue =
      state != null &&
      state.sessionReady &&
      !state.controlComplete &&
      !state.closeRequested &&
      state.outstandingRequests.size === 0;
    if (!canIssue) {
      return commands;
    }
    if (!this.benchmarkAcceptsNewWork()) {
      commands.push(...this.maybeCloseCrrConnection(connection));
      return commands;
    }
    commands.push(...this.issueRequest(connection, now));
    return commands;
  }

  issueRequest(connection, now) {
    const streamId = this.nextStreamId(connection);
    const counts = this.config.requests != null || this.phase === BenchmarkPhase.MEASURE;
    const state = this.connections.get(connection);
    if (state == null) {
      throw new PerfError("request for unknown connection");
    }
    state.outstandingRequests.set(streamId, new OutstandingRequest(now, counts));
    state.requestsStarted += 1;
    if (counts) {
      this.summary.bytes_sent += this.config.requestBytes;
    }
    return [
      new SendStreamCommand(connection, streamId, makePayload(this.config.requestBytes), true),
    ];
  }

  async maybeOpenCrrConnections() {
    if (this.config.mode !== Mode.CRR || !this.benchmarkAcceptsNewWork()) {
      return;
    }
    while (
      this.connections.size < this.config.connections &&
      (this.config.requests == null || this.crrRequestsOpened < this.config.requests)
    ) {
      const now = this.io.nowUs();
      const result = this.executeCommand(new OpenConnectionCommand(), now);
      this.crrRequestsOpened += 1;
      if (result != null) {
        await this.handleResult(result, now);
      }
    }
  }

  maybeCloseRrConnection(connection) {
    const force = this.timedRrMode() && this.phase === BenchmarkPhase.DRAIN;
    const state = this.connections.get(connection);
    if (
      state == null ||
      state.closeRequested ||
      (!force && state.outstandingRequests.size > 0)
    ) {
      return [];
    }
    return this.closeConnection(connection, Buffer.from("timed rr drain complete"));
  }

  maybeFinishPersistentRrStream(connection) {
    const state = this.connections.get(connection);
    if (state == null) {
      return [];
    }
    if (state.persistentStreamId == null) {
      return this.phase === BenchmarkPhase.DRAIN && state.persistentRequests.length === 0
        ? this.maybeClosePersistentRrConnection(connection)
        : [];
    }
    if (state.persistentFinSent) {
      return this.phase === BenchmarkPhase.DRAIN && state.persistentRequests.length === 0
        ? this.maybeClosePersistentRrConnection(connection)
        : [];
    }
    state.persistentFinSent = true;
    const commands = [
      new SendStreamCommand(connection, state.persistentStreamId, Buffer.alloc(0), true),
    ];
    if (this.phase === BenchmarkPhase.DRAIN && state.persistentRequests.length === 0) {
      commands.push(...this.maybeClosePersistentRrConnection(connection));
    }
    return commands;
  }

  maybeClosePersistentRrConnection(connection) {
    const force = this.timedPersistentRrMode() && this.phase === BenchmarkPhase.DRAIN;
    const state = this.connections.get(connection);
    if (
      state == null ||
      state.closeRequested ||
      (!force && state.persistentRequests.length > 0)
    ) {
      return [];
    }
    if (!state.persistentFinSent) {
      return this.maybeFinishPersistentRrStream(connection);
    }
    return this.closeConnection(connection, Buffer.from("persistent rr drain complete"));
  }

  maybeCloseBulkConnection(connection) {
    const state = this.connections.get(connection);
    if (state == null || state.closeRequested || state.activeBulkStreams.size > 0) {
      return [];
    }
    return this.closeConnection(connection, Buffer.from("timed bulk drain complete"));
  }

  maybeCloseCrrConnection(connection) {
    const force = this.timedCrrMode() && this.phase === BenchmarkPhase.DRAIN;
    const state = this.connections.get(connection);
    if (
      state == null ||
      state.closeRequested ||
      (!force && state.outstandingRequests.size > 0)
    ) {
      return [];
    }
    return this.closeConnection(connection, Buffer.from("timed crr drain complete"));
  }

  closeConnection(connection, reason) {
    const state = this.connections.get(connection);
    if (state != null) {
      if (state.closeRequested) {
        return [];
      }
      state.closeRequested = true;
    }
    this.closingConnections.add(connection);
    return [new CloseCommand(connection, reason)];
  }

  async advanceBenchmarkPhase(now) {
    this.advanceBenchmarkPhaseSync(now);
    if (this.phase === BenchmarkPhase.MEASURE && now >= this.measureDeadline) {
      await this.enterDrainPhase(now);
    }
    await this.forceCloseTimedDrain(now);
  }

  advanceBenchmarkPhaseSync(now) {
    if (this.benchmarkStartedAt == null || !this.timedMode()) {
      return;
    }
    if (
      this.phase === BenchmarkPhase.WARMUP &&
      now - this.benchmarkStartedAt >= durationUs(this.config.warmup)
    ) {
      this.enterMeasurePhase(now);
    }
  }

  async forceCloseTimedDrain(now) {
    if (
      !this.timedMode() ||
      this.phase !== BenchmarkPhase.DRAIN ||
      this.drainDeadline == null ||
      now < this.drainDeadline
    ) {
      return;
    }

    for (const handle of Array.from(this.connections.keys())) {
      let commands = [];
      const state = this.connections.get(handle);
      if (this.config.mode === Mode.BULK) {
        state?.activeBulkStreams.clear();
        commands = this.maybeCloseBulkConnection(handle);
      } else if (this.config.mode === Mode.RR) {
        commands = this.maybeCloseRrConnection(handle);
      } else if (this.config.mode === Mode.PERSISTENT_RR) {
        if (state != null) {
          state.persistentFinSent = true;
        }
        commands = this.maybeClosePersistentRrConnection(handle);
      } else if (this.config.mode === Mode.CRR) {
        commands = this.maybeCloseCrrConnection(handle);
      }
      for (const command of commands) {
        const result = this.executeCommand(command, now);
        if (result != null) {
          await this.handleResult(result, now);
        }
      }
    }
  }

  maybeStartTimedBenchmark(now) {
    if (!this.timedMode() || this.benchmarkStartedAt != null) {
      return;
    }
    this.benchmarkStartedAt = now;
    this.runStartedAt = now;
    this.measureStartedAt = now;
    this.phase = BenchmarkPhase.WARMUP;
    if (this.config.warmup === 0) {
      this.enterMeasurePhase(now);
    }
  }

  enterMeasurePhase(now) {
    this.phase = BenchmarkPhase.MEASURE;
    this.measureStartedAt = now;
    this.measureDeadline = now + durationUs(this.config.duration);
    resetMeasurement(this.summary);
    for (const state of this.connections.values()) {
      for (const request of state.outstandingRequests.values()) {
        request.countsTowardMeasurement = false;
      }
      for (const request of state.persistentRequests) {
        request.countsTowardMeasurement = false;
      }
      for (const streamId of state.activeBulkStreams.keys()) {
        state.activeBulkStreams.set(streamId, true);
      }
    }
  }

  async enterDrainPhase(now) {
    if (this.phase === BenchmarkPhase.DRAIN) {
      return;
    }
    this.phase = BenchmarkPhase.DRAIN;
    this.summary.elapsed_ms = durationMillis(this.resultElapsedSeconds(now));
    if (this.timedMode()) {
      this.drainDeadline = now + durationUs(Math.min(this.config.duration, DRAIN_TIMEOUT));
    }

    for (const handle of Array.from(this.connections.keys())) {
      let commands = [];
      if (this.config.mode === Mode.RR) {
        commands = this.maybeCloseRrConnection(handle);
      } else if (this.config.mode === Mode.PERSISTENT_RR) {
        commands = this.maybeFinishPersistentRrStream(handle);
      } else if (this.config.mode === Mode.CRR) {
        commands = this.maybeCloseCrrConnection(handle);
      } else if (this.timedBulkMode()) {
        commands = this.maybeCloseBulkConnection(handle);
      }
      for (const command of commands) {
        const result = this.executeCommand(command, now);
        if (result != null) {
          await this.handleResult(result, now);
        }
      }
    }
  }

  timedRrMode() {
    return this.config.mode === Mode.RR && this.config.requests == null;
  }

  timedPersistentRrMode() {
    return this.config.mode === Mode.PERSISTENT_RR && this.config.requests == null;
  }

  timedCrrMode() {
    return this.config.mode === Mode.CRR && this.config.requests == null;
  }

  timedBulkMode() {
    return this.config.mode === Mode.BULK && this.config.totalBytes == null;
  }

  timedMode() {
    return (
      this.timedRrMode() ||
      this.timedPersistentRrMode() ||
      this.timedCrrMode() ||
      this.timedBulkMode()
    );
  }

  benchmarkAcceptsNewWork() {
    return this.phase !== BenchmarkPhase.DRAIN;
  }

  canWaitThroughIdle() {
    return this.timedBulkMode() && this.benchmarkStartedAt != null;
  }

  benchmarkNextWakeup() {
    if (!this.timedMode() || this.benchmarkStartedAt == null) {
      return null;
    }
    if (this.phase === BenchmarkPhase.WARMUP) {
      return this.benchmarkStartedAt + durationUs(this.config.warmup);
    }
    if (this.phase === BenchmarkPhase.MEASURE) {
      return this.measureDeadline;
    }
    if (this.phase === BenchmarkPhase.DRAIN) {
      return this.drainDeadline;
    }
    return null;
  }

  nextWaitWakeup(coreNextWakeup) {
    coreNextWakeup = timeUsToNumber(coreNextWakeup);
    const benchmark = this.benchmarkNextWakeup();
    const values = [coreNextWakeup, benchmark].filter((value) => value != null);
    return values.length > 0 ? Math.min(...values) : null;
  }

  resultElapsedSeconds(now) {
    if (this.timedMode()) {
      if (this.phase === BenchmarkPhase.WARMUP) {
        return 0.0;
      }
      const measurementNow = this.phase === BenchmarkPhase.DRAIN ? this.measureDeadline : now;
      return Math.max(measurementNow - this.measureStartedAt, 0) / 1_000_000.0;
    }
    return Math.max(now - this.runStartedAt, 0) / 1_000_000.0;
  }

  runComplete() {
    if (this.config.mode !== Mode.CRR && this.connections.size === 0) {
      return false;
    }

    if (this.config.mode === Mode.BULK) {
      if (this.timedBulkMode()) {
        return (
          this.phase === BenchmarkPhase.DRAIN &&
          Array.from(this.connections.values()).every(
            (state) => state.closeRequested && state.activeBulkStreams.size === 0,
          )
        );
      }
      const controlComplete = Array.from(this.connections.values()).every(
        (state) => state.controlComplete,
      );
      if (!controlComplete) {
        return false;
      }
      if (this.config.totalBytes != null) {
        if (this.config.direction === Direction.DOWNLOAD) {
          return this.summary.bytes_received >= this.config.totalBytes;
        }
        return this.summary.bytes_sent >= this.config.totalBytes;
      }
      return true;
    }

    if (this.config.mode === Mode.RR) {
      if (this.timedRrMode()) {
        return (
          this.phase === BenchmarkPhase.DRAIN &&
          Array.from(this.connections.values()).every((state) => state.closeRequested)
        );
      }
      return (
        this.config.requests != null &&
        this.summary.requests_completed >= this.config.requests &&
        Array.from(this.connections.values()).every(
          (state) => state.controlComplete && state.outstandingRequests.size === 0,
        )
      );
    }

    if (this.config.mode === Mode.PERSISTENT_RR) {
      if (this.timedPersistentRrMode()) {
        return (
          this.phase === BenchmarkPhase.DRAIN &&
          Array.from(this.connections.values()).every((state) => state.closeRequested)
        );
      }
      return (
        this.config.requests != null &&
        this.summary.requests_completed >= this.config.requests &&
        Array.from(this.connections.values()).every(
          (state) => state.controlComplete && state.persistentRequests.length === 0,
        )
      );
    }

    if (this.timedCrrMode()) {
      return (
        this.phase === BenchmarkPhase.DRAIN &&
        Array.from(this.connections.values()).every((state) => state.closeRequested)
      );
    }
    return (
      this.config.requests != null &&
      this.summary.requests_completed >= this.config.requests &&
      this.connections.size === 0
    );
  }

  initialConnectionTarget() {
    if (this.config.mode === Mode.CRR) {
      return 0;
    }
    return rrConnectionTarget(this.config);
  }

  makeClientConfig(index) {
    const sequence = index + 1;
    const config = ClientConfig.new(
      makeConnectionId(0xc1, sequence),
      makeConnectionId(0x83, 0x40 + sequence),
    );
    config.core.serverName = Buffer.from(this.config.serverName);
    return config;
  }

  makeSessionStart(requestLimit = null) {
    return new SessionStart({
      protocolVersion: PROTOCOL_VERSION,
      mode: this.config.mode,
      direction: this.config.direction,
      requestBytes: this.config.requestBytes,
      responseBytes: this.config.responseBytes,
      totalBytes: this.config.totalBytes,
      requests: requestLimit ?? this.config.requests,
      warmup: this.config.warmup,
      duration: this.config.duration,
      streams: this.config.streams,
      connections: this.config.connections,
      requestsInFlight: this.config.requestsInFlight,
    });
  }

  nextStreamId(connection) {
    const state = this.connections.get(connection);
    if (state == null) {
      throw new PerfError("unknown connection");
    }
    const streamId = state.nextStreamId;
    state.nextStreamId = nextClientStreamId(streamId);
    return streamId;
  }
}

function makePayload(size) {
  return Buffer.alloc(size, 0x5a);
}

function requestLimitForConnection(config, connectionIndex) {
  if (
    (config.mode !== Mode.RR && config.mode !== Mode.PERSISTENT_RR) ||
    config.requests == null
  ) {
    return null;
  }
  const connections = rrConnectionTarget(config);
  const base = Math.floor(config.requests / connections);
  const remainder = config.requests % connections;
  return base + (connectionIndex < remainder ? 1 : 0);
}

function rrConnectionTarget(config) {
  if ((config.mode === Mode.RR || config.mode === Mode.PERSISTENT_RR) && config.requests != null) {
    return Math.min(config.connections, config.requests);
  }
  return config.connections;
}

function makeConnectionId(prefix, sequence) {
  const value = Buffer.alloc(8);
  value[0] = prefix;
  for (let index = 1; index < value.length; index += 1) {
    const shift = (value.length - 1 - index) * 8;
    value[index] = (sequence >> shift) & 0xff;
  }
  return value;
}

function durationUs(seconds) {
  return Math.min(Math.trunc(seconds * 1_000_000), Number.MAX_SAFE_INTEGER);
}

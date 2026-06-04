import fs from "node:fs";

import {
  CongestionControl,
  EndpointConfig,
  Role as CoquicRole,
  TlsIdentity,
} from "@coquic/coquic";

import { PerfError } from "./error.mjs";

export const APPLICATION_PROTOCOL = Buffer.from("coquic-perf/1");
export const PERF_MAX_OUTBOUND_DATAGRAM_SIZE = 1472;
export const PERF_PMTUD_MAX_DATAGRAM_SIZE = 0;
export const PERF_MIN_UDP_PAYLOAD_SIZE = 1200;
export const PERF_TRANSFER_CONNECTION_RECEIVE_WINDOW = 32 * 1024 * 1024;
export const PERF_TRANSFER_STREAM_RECEIVE_WINDOW = 16 * 1024 * 1024;
export const PERF_ACK_ELICITING_THRESHOLD = 2;
export const PERF_COPA_BULK_ACK_ELICITING_THRESHOLD = 1;
export const PERF_COPA_INTERACTIVE_ACK_ELICITING_THRESHOLD = 8;
export const PERF_SERVER_INITIAL_MAX_BIDIRECTIONAL_STREAMS = 4096;

export const Role = Object.freeze({
  SERVER: "server",
  CLIENT: "client",
});

export const Mode = Object.freeze({
  BULK: "bulk",
  RR: "rr",
  CRR: "crr",
});

export const Direction = Object.freeze({
  UPLOAD: "upload",
  DOWNLOAD: "download",
});

export class PerfConfig {
  constructor() {
    this.role = Role.SERVER;
    this.mode = Mode.BULK;
    this.direction = Direction.DOWNLOAD;
    this.host = "127.0.0.1";
    this.port = 4433;
    this.serverName = "localhost";
    this.verifyPeer = false;
    this.certificateChainPath = "tests/fixtures/quic-server-cert.pem";
    this.privateKeyPath = "tests/fixtures/quic-server-key.pem";
    this.jsonOut = null;
    this.requestBytes = 64;
    this.responseBytes = 64;
    this.streams = 1;
    this.connections = 1;
    this.requestsInFlight = 1;
    this.requests = null;
    this.totalBytes = null;
    this.maxOutboundDatagramSize = PERF_MAX_OUTBOUND_DATAGRAM_SIZE;
    this.pmtudMaxDatagramSize = PERF_PMTUD_MAX_DATAGRAM_SIZE;
    this.warmup = 0.0;
    this.duration = 5.0;
    this.congestionControl = CongestionControl.NEWRENO;
  }
}

export function parseRuntimeArgs(args) {
  if (args.length === 0) {
    throw new PerfError(usage());
  }

  const config = new PerfConfig();
  config.role = parseRole(args[0]);

  let sawDirection = false;
  let index = 1;
  while (index < args.length) {
    const arg = args[index++];
    if (arg === "--verify-peer") {
      config.verifyPeer = true;
      continue;
    }
    if (index >= args.length) {
      throw new PerfError(`missing value for ${arg}\n${usage()}`);
    }
    const value = args[index++];
    if (arg === "--direction") {
      sawDirection = true;
    }
    applyOption(config, arg, value);
  }

  if (config.mode !== Mode.BULK && sawDirection) {
    throw new PerfError(usage());
  }
  if (config.streams === 0 || config.connections === 0 || config.requestsInFlight === 0) {
    throw new PerfError(usage());
  }
  return config;
}

export function clientEndpointConfig(config) {
  const endpoint = new EndpointConfig();
  endpoint.role = CoquicRole.CLIENT;
  endpoint.verifyPeer = config.verifyPeer;
  endpoint.applicationProtocol = APPLICATION_PROTOCOL;
  endpoint.maxOutboundDatagramSize = config.maxOutboundDatagramSize;
  endpoint.emitSharedReceiveStreamData = true;
  applyTransportDefaults(config, endpoint.transport);
  return endpoint;
}

export function serverEndpointConfig(config) {
  const endpoint = new EndpointConfig();
  endpoint.role = CoquicRole.SERVER;
  endpoint.verifyPeer = config.verifyPeer;
  endpoint.applicationProtocol = APPLICATION_PROTOCOL;
  endpoint.identity = new TlsIdentity({
    certificatePem: readFile(config.certificateChainPath),
    privateKeyPem: readFile(config.privateKeyPath),
  });
  endpoint.maxOutboundDatagramSize = config.maxOutboundDatagramSize;
  endpoint.emitSharedReceiveStreamData = true;
  applyTransportDefaults(config, endpoint.transport);
  endpoint.transport.initialMaxStreamsBidi = Math.max(
    endpoint.transport.initialMaxStreamsBidi,
    PERF_SERVER_INITIAL_MAX_BIDIRECTIONAL_STREAMS,
  );
  return endpoint;
}

export function applyTransportDefaults(config, transport) {
  transport.congestionControl = config.congestionControl;
  transport.enableHystartPlusPlus = perfEnableHystartPlusPlus(config);
  transport.sendStreamFairness = perfSendStreamFairness(config);
  transport.ackElicitingThreshold = perfAckElicitingThreshold(config);
  transport.pmtudMaxDatagramSize = config.pmtudMaxDatagramSize;
  transport.initialMaxData = PERF_TRANSFER_CONNECTION_RECEIVE_WINDOW;
  transport.initialMaxStreamDataBidiLocal = PERF_TRANSFER_STREAM_RECEIVE_WINDOW;
  transport.initialMaxStreamDataBidiRemote = PERF_TRANSFER_STREAM_RECEIVE_WINDOW;
}

export function congestionControlName(value) {
  const names = {
    [CongestionControl.NEWRENO]: "newreno",
    [CongestionControl.CUBIC]: "cubic",
    [CongestionControl.BBR]: "bbr",
    [CongestionControl.COPA]: "copa",
  };
  return names[value];
}

function applyOption(config, arg, value) {
  if (arg === "--host") {
    config.host = value;
  } else if (arg === "--server-name") {
    config.serverName = value;
  } else if (arg === "--json-out") {
    config.jsonOut = value;
  } else if (arg === "--certificate-chain") {
    config.certificateChainPath = value;
  } else if (arg === "--private-key") {
    config.privateKeyPath = value;
  } else if (arg === "--port") {
    config.port = parseSize(value);
    if (config.port > 65535) {
      throw new PerfError(usage());
    }
  } else if (arg === "--io-backend") {
    if (value !== "socket") {
      throw new PerfError("coquic-js-perf currently supports --io-backend socket");
    }
  } else if (arg === "--congestion-control") {
    config.congestionControl = parseCongestionControl(value);
  } else if (arg === "--mode") {
    config.mode = parseMode(value);
  } else if (arg === "--direction") {
    config.direction = parseDirection(value);
  } else if (arg === "--warmup") {
    config.warmup = parseDuration(value);
  } else if (arg === "--duration") {
    config.duration = parseDuration(value);
  } else if (arg in numericOptions) {
    config[numericOptions[arg]] = parseSize(value);
    if (
      arg === "--max-outbound-datagram-size" &&
      config.maxOutboundDatagramSize < PERF_MIN_UDP_PAYLOAD_SIZE
    ) {
      throw new PerfError(usage());
    }
    if (
      arg === "--pmtud-max-datagram-size" &&
      config.pmtudMaxDatagramSize !== 0 &&
      config.pmtudMaxDatagramSize < PERF_MIN_UDP_PAYLOAD_SIZE
    ) {
      throw new PerfError(usage());
    }
  } else {
    throw new PerfError(usage());
  }
}

const numericOptions = Object.freeze({
  "--request-bytes": "requestBytes",
  "--response-bytes": "responseBytes",
  "--streams": "streams",
  "--connections": "connections",
  "--requests-in-flight": "requestsInFlight",
  "--requests": "requests",
  "--total-bytes": "totalBytes",
  "--max-outbound-datagram-size": "maxOutboundDatagramSize",
  "--pmtud-max-datagram-size": "pmtudMaxDatagramSize",
});

function parseRole(value) {
  if (value === Role.SERVER || value === Role.CLIENT) {
    return value;
  }
  throw new PerfError(usage());
}

function parseMode(value) {
  if (value === Mode.BULK || value === Mode.RR || value === Mode.CRR) {
    return value;
  }
  throw new PerfError(usage());
}

function parseDirection(value) {
  if (value === Direction.UPLOAD || value === Direction.DOWNLOAD) {
    return value;
  }
  throw new PerfError(usage());
}

function parseCongestionControl(value) {
  const mapping = {
    newreno: CongestionControl.NEWRENO,
    cubic: CongestionControl.CUBIC,
    bbr: CongestionControl.BBR,
    copa: CongestionControl.COPA,
  };
  if (value in mapping) {
    return mapping[value];
  }
  throw new PerfError(usage());
}

function parseDuration(value) {
  if (value.endsWith("ms")) {
    return Number.parseInt(value.slice(0, -2), 10) / 1000.0;
  }
  if (value.endsWith("s")) {
    return Number.parseInt(value.slice(0, -1), 10);
  }
  throw new PerfError("duration must use ms or s suffix");
}

function parseSize(value) {
  return Number.parseInt(value, 10);
}

function perfAckElicitingThreshold(config) {
  if (config.congestionControl === CongestionControl.COPA) {
    return config.mode === Mode.BULK
      ? PERF_COPA_BULK_ACK_ELICITING_THRESHOLD
      : PERF_COPA_INTERACTIVE_ACK_ELICITING_THRESHOLD;
  }
  return PERF_ACK_ELICITING_THRESHOLD;
}

function perfEnableHystartPlusPlus(config) {
  if (config.mode !== Mode.BULK) {
    return true;
  }
  return ![CongestionControl.NEWRENO, CongestionControl.CUBIC].includes(
    config.congestionControl,
  );
}

function perfSendStreamFairness(config) {
  return config.mode !== Mode.BULK;
}

function readFile(path) {
  try {
    return fs.readFileSync(path);
  } catch (error) {
    throw new PerfError(`failed to read ${path}: ${error.message}`);
  }
}

export function usage() {
  return (
    "usage: coquic-js-perf [server|client] [--host HOST] [--port PORT] " +
    "[--io-backend socket] [--congestion-control newreno|cubic|bbr|copa] " +
    "[--mode bulk|rr|crr] [--direction upload|download] [--request-bytes N] " +
    "[--response-bytes N] [--streams N] [--connections N] " +
    "[--requests-in-flight N] [--requests N] [--total-bytes N] " +
    "[--warmup 250ms|2s] [--duration 250ms|2s] " +
    "[--max-outbound-datagram-size N] [--pmtud-max-datagram-size N] " +
    "[--certificate-chain PATH] [--private-key PATH] [--server-name NAME] " +
    "[--verify-peer] [--json-out PATH]"
  );
}

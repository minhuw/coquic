import fs from "node:fs";

import { APPLICATION_PROTOCOL, congestionControlName } from "./config.mjs";
import { PerfError } from "./error.mjs";

export function newRunSummary(config) {
  return {
    schema_version: 1,
    status: "ok",
    mode: config.mode,
    direction: config.direction,
    backend: "dgram",
    congestion_control: congestionControlName(config.congestionControl),
    remote_host: config.host,
    remote_port: config.port,
    alpn: APPLICATION_PROTOCOL.toString(),
    elapsed_ms: 0,
    warmup_ms: durationMillis(config.warmup),
    bytes_sent: 0,
    bytes_received: 0,
    server_counters: newServerCounters(),
    requests_completed: 0,
    streams: config.streams,
    connections: config.connections,
    requests_in_flight: config.requestsInFlight,
    request_bytes: config.requestBytes,
    response_bytes: config.responseBytes,
    throughput_mib_per_s: 0.0,
    throughput_gbit_per_s: 0.0,
    requests_per_s: 0.0,
    latency: summarizeLatencySamples([]),
    latency_samples: [],
  };
}

export function newServerCounters() {
  return {
    bytes_sent: 0,
    bytes_received: 0,
    requests_completed: 0,
  };
}

export function resetMeasurement(summary) {
  summary.elapsed_ms = 0;
  summary.bytes_sent = 0;
  summary.bytes_received = 0;
  summary.server_counters = newServerCounters();
  summary.requests_completed = 0;
  summary.latency = summarizeLatencySamples([]);
  summary.latency_samples = [];
  summary.throughput_mib_per_s = 0.0;
  summary.throughput_gbit_per_s = 0.0;
  summary.requests_per_s = 0.0;
}

export function finalizeSummary(summary) {
  summary.latency = summarizeLatencySamples(summary.latency_samples);
  const seconds = Math.max(summary.elapsed_ms, 1) / 1000.0;
  const transferBytes = summary.bytes_sent + summary.bytes_received;
  summary.throughput_mib_per_s = transferBytes / (1024.0 * 1024.0) / seconds;
  summary.throughput_gbit_per_s = (transferBytes * 8.0) / 1_000_000_000.0 / seconds;
  summary.requests_per_s = summary.requests_completed / seconds;
}

export function emitSummary(summary, jsonOut) {
  console.log(renderSummary(summary));
  if (jsonOut != null) {
    try {
      fs.writeFileSync(jsonOut, JSON.stringify(summaryDict(summary)));
    } catch (error) {
      throw new PerfError(`failed to write ${jsonOut}: ${error.message}`);
    }
  }
}

export function renderSummary(summary) {
  return (
    `status=${summary.status} mode=${summary.mode} cc=${summary.congestion_control} ` +
    `direction=${summary.direction} throughput_mib/s=${summary.throughput_mib_per_s.toFixed(3)} ` +
    `throughput_gbit/s=${summary.throughput_gbit_per_s.toFixed(3)} ` +
    `requests/s=${summary.requests_per_s.toFixed(3)}`
  );
}

export function summarizeLatencySamples(samples) {
  if (samples.length === 0) {
    return {
      min_us: 0,
      avg_us: 0,
      p50_us: 0,
      p90_us: 0,
      p99_us: 0,
      max_us: 0,
    };
  }
  const micros = samples.map(durationMicros).sort((a, b) => a - b);
  const total = micros.reduce((sum, value) => sum + value, 0);
  return {
    min_us: micros[0],
    avg_us: Math.trunc(total / micros.length),
    p50_us: percentileValue(micros, 50),
    p90_us: percentileValue(micros, 90),
    p99_us: percentileValue(micros, 99),
    max_us: micros[micros.length - 1],
  };
}

export function durationMillis(seconds) {
  return Math.min(Math.trunc(seconds * 1000), Number.MAX_SAFE_INTEGER);
}

function durationMicros(seconds) {
  return Math.min(Math.trunc(seconds * 1_000_000), Number.MAX_SAFE_INTEGER);
}

function percentileValue(sortedValues, percentile) {
  const rank = Math.trunc((percentile / 100.0) * sortedValues.length + 0.999999);
  const index = rank === 0 ? 0 : Math.min(rank - 1, sortedValues.length - 1);
  return sortedValues[index];
}

function summaryDict(summary) {
  const data = { ...summary };
  delete data.latency_samples;
  if (data.failure_reason == null) {
    delete data.failure_reason;
  }
  return data;
}

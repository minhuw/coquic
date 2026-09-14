const LIVE_PATH = "/api/steward/live";
const WS_PATH = `${LIVE_PATH}/ws`;
const MAX_BODY_BYTES = 16 * 1024;
const MAX_FUTURE_SKEW_MS = 5 * 60 * 1000;
const SNAPSHOT_KEY = "snapshot";
const JSON_HEADERS = {
  "access-control-allow-origin": "*",
  "cache-control": "no-store",
  "content-type": "application/json; charset=utf-8",
};

function jsonResponse(body, status = 200, headers = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...JSON_HEADERS, ...headers },
  });
}

function errorResponse(status, error, headers = {}) {
  return jsonResponse({ error }, status, headers);
}

function hasExactKeys(value, keys) {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.keys(value).length === keys.length &&
    keys.every((key) => Object.hasOwn(value, key))
  );
}

function isCount(value) {
  return Number.isSafeInteger(value) && value >= 0;
}

function isUtcTimestamp(value) {
  if (typeof value !== "string") return false;
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?Z$/.exec(value);
  if (!match) return false;
  const [, year, month, day, hour, minute, second] = match.map(Number);
  const date = new Date(0);
  date.setUTCFullYear(year, month - 1, day);
  date.setUTCHours(hour, minute, second, 0);
  return (
    date.getUTCFullYear() === year &&
    date.getUTCMonth() === month - 1 &&
    date.getUTCDate() === day &&
    date.getUTCHours() === hour &&
    date.getUTCMinutes() === minute &&
    date.getUTCSeconds() === second
  );
}

export function validateSnapshot(value) {
  return (
    hasExactKeys(value, [
      "schemaVersion",
      "observedAt",
      "staleAfterSeconds",
      "daemon",
      "signals",
      "planning",
      "tasks",
      "integration",
    ]) &&
    value.schemaVersion === "1.0" &&
    isUtcTimestamp(value.observedAt) &&
    Number.isInteger(value.staleAfterSeconds) &&
    value.staleAfterSeconds >= 30 &&
    value.staleAfterSeconds <= 3600 &&
    hasExactKeys(value.daemon, ["mode"]) &&
    ["production", "dry-run"].includes(value.daemon.mode) &&
    hasExactKeys(value.signals, ["pending"]) &&
    isCount(value.signals.pending) &&
    hasExactKeys(value.planning, ["state"]) &&
    ["active", "idle", "paused"].includes(value.planning.state) &&
    hasExactKeys(value.tasks, ["active", "queued"]) &&
    isCount(value.tasks.active) &&
    isCount(value.tasks.queued) &&
    hasExactKeys(value.integration, ["active", "queued"]) &&
    isCount(value.integration.active) &&
    isCount(value.integration.queued)
  );
}

export function withAvailability(snapshot, now = Date.now()) {
  return {
    ...snapshot,
    availability:
      now < Date.parse(snapshot.observedAt) + snapshot.staleAfterSeconds * 1000
        ? "live"
        : "stale",
  };
}

function authorized(header, expected) {
  if (
    typeof header !== "string" ||
    typeof expected !== "string" ||
    expected.length === 0 ||
    header.length > 512
  ) {
    return false;
  }
  const actual = header.startsWith("Bearer ") ? header.slice(7) : "";
  let difference = actual.length ^ expected.length;
  const length = Math.max(actual.length, expected.length);
  for (let index = 0; index < length; index += 1) {
    difference |= (actual.charCodeAt(index) || 0) ^ (expected.charCodeAt(index) || 0);
  }
  return difference === 0;
}

async function readBody(request) {
  if (request.body === null) return new Uint8Array();
  const reader = request.body.getReader();
  const chunks = [];
  let length = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    length += value.byteLength;
    if (length > MAX_BODY_BYTES) {
      await reader.cancel();
      return null;
    }
    chunks.push(value);
  }
  const body = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return body;
}

async function readSnapshot(request, token, now = Date.now()) {
  if (!authorized(request.headers.get("authorization"), token)) {
    return [null, errorResponse(401, "unauthorized", { "www-authenticate": "Bearer" })];
  }
  if ((request.headers.get("content-type") || "").split(";", 1)[0].trim().toLowerCase() !== "application/json") {
    return [null, errorResponse(415, "unsupported_media_type")];
  }
  const declaredLength = request.headers.get("content-length");
  if (declaredLength !== null && !/^\d+$/.test(declaredLength)) {
    return [null, errorResponse(400, "invalid_request")];
  }
  if (declaredLength !== null && Number(declaredLength) > MAX_BODY_BYTES) {
    return [null, errorResponse(413, "payload_too_large")];
  }
  const bytes = await readBody(request);
  if (bytes === null) return [null, errorResponse(413, "payload_too_large")];
  let value;
  try {
    value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    return [null, errorResponse(400, "invalid_json")];
  }
  if (!validateSnapshot(value)) {
    return [null, errorResponse(400, "invalid_payload")];
  }
  if (Date.parse(value.observedAt) > now + MAX_FUTURE_SKEW_MS) {
    return [null, errorResponse(400, "invalid_payload")];
  }
  return [value, null];
}

export class LiveState {
  constructor(state, env) {
    this.state = state;
    this.env = env;
  }

  async fetch(request) {
    const url = new URL(request.url);
    if (url.pathname === LIVE_PATH && request.method === "GET") {
      const snapshot = await this.state.storage.get(SNAPSHOT_KEY);
      return snapshot
        ? jsonResponse(withAvailability(snapshot))
        : errorResponse(503, "unavailable");
    }
    if (url.pathname === LIVE_PATH && request.method === "POST") {
      const [snapshot, failure] = await readSnapshot(request, this.env.WRITE_TOKEN);
      if (failure) return failure;
      const previous = await this.state.storage.get(SNAPSHOT_KEY);
      if (previous && Date.parse(snapshot.observedAt) <= Date.parse(previous.observedAt)) {
        return errorResponse(409, "stale_update");
      }
      await this.state.storage.put(SNAPSHOT_KEY, snapshot);
      const current = withAvailability(snapshot);
      const message = JSON.stringify(current);
      for (const socket of this.state.getWebSockets()) {
        try {
          socket.send(message);
        } catch {
          socket.close(1011, "update_failed");
        }
      }
      return jsonResponse(current);
    }
    if (url.pathname === WS_PATH && request.method === "GET") {
      if ((request.headers.get("upgrade") || "").toLowerCase() !== "websocket") {
        return errorResponse(426, "upgrade_required");
      }
      const snapshot = await this.state.storage.get(SNAPSHOT_KEY);
      if (!snapshot) return errorResponse(503, "unavailable");
      const pair = new WebSocketPair();
      const [client, server] = Object.values(pair);
      this.state.acceptWebSocket(server);
      server.send(JSON.stringify(withAvailability(snapshot)));
      return new Response(null, { status: 101, webSocket: client });
    }
    if (url.pathname === LIVE_PATH) {
      return errorResponse(405, "method_not_allowed", { allow: "GET, POST" });
    }
    if (url.pathname === WS_PATH) {
      return errorResponse(405, "method_not_allowed", { allow: "GET" });
    }
    return errorResponse(404, "not_found");
  }

  webSocketMessage() {}

  webSocketClose() {}
}

export default {
  fetch(request, env) {
    const id = env.LIVE_STATE.idFromName("global");
    return env.LIVE_STATE.get(id).fetch(request);
  },
};

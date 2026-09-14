import assert from "node:assert/strict";
import test from "node:test";

import worker, {
  LiveState,
  validateSnapshot,
  withAvailability,
} from "../live-state-worker.mjs";

const snapshot = {
  schemaVersion: "1.0",
  observedAt: "2026-06-12T10:20:30.123Z",
  staleAfterSeconds: 60,
  daemon: { mode: "production" },
  signals: { pending: 1 },
  planning: { state: "active" },
  tasks: { active: 2, queued: 3 },
  integration: { active: 1, queued: 0 },
};

function durable(initial) {
  const values = new Map(initial ? [["snapshot", initial]] : []);
  const messages = [];
  const state = {
    storage: {
      get: async (key) => values.get(key),
      put: async (key, value) => values.set(key, value),
    },
    getWebSockets: () => [{ send: (message) => messages.push(message) }],
    acceptWebSocket: () => {},
  };
  return { object: new LiveState(state, { WRITE_TOKEN: "write-token" }), messages };
}

test("validation accepts only the closed producer contract", () => {
  assert.equal(validateSnapshot(snapshot), true);
  assert.equal(validateSnapshot({ ...snapshot, availability: "live" }), false);
  assert.equal(validateSnapshot({ ...snapshot, observedAt: "2026-02-30T00:00:00Z" }), false);
  assert.equal(validateSnapshot({ ...snapshot, observedAt: "2026-06-12T10:20:30.1234567890Z" }), false);
  assert.equal(validateSnapshot({ ...snapshot, staleAfterSeconds: 29 }), false);
  assert.equal(validateSnapshot({ ...snapshot, tasks: { active: -1, queued: 0 } }), false);
  assert.equal(validateSnapshot({ ...snapshot, signals: { pending: Number.MAX_SAFE_INTEGER + 1 } }), false);
  assert.equal(validateSnapshot({ ...snapshot, daemon: { mode: "production", extra: true } }), false);
});

test("availability uses the producer timestamp and stale window", () => {
  assert.equal(withAvailability(snapshot, Date.parse(snapshot.observedAt) + 59_999).availability, "live");
  assert.equal(withAvailability(snapshot, Date.parse(snapshot.observedAt) + 60_000).availability, "stale");
});

test("storage starts unavailable, authenticates updates, and broadcasts accepted state", async () => {
  const { object, messages } = durable();
  const missing = await object.fetch(new Request("https://live.example/api/steward/live"));
  assert.equal(missing.status, 503);
  assert.deepEqual(await missing.json(), { error: "unavailable" });

  const denied = await object.fetch(
    new Request("https://live.example/api/steward/live", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(snapshot),
    }),
  );
  assert.equal(denied.status, 401);
  assert.doesNotMatch(await denied.text(), /write-token/);

  const rejectedValue = "private-task-id";
  const rejected = await object.fetch(
    new Request("https://live.example/api/steward/live", {
      method: "POST",
      headers: {
        authorization: "Bearer write-token",
        "content-type": "application/json",
      },
      body: JSON.stringify({ ...snapshot, taskId: rejectedValue }),
    }),
  );
  const rejectedBody = await rejected.text();
  assert.equal(rejected.status, 400);
  assert.ok(rejectedBody.length < 128);
  assert.doesNotMatch(rejectedBody, new RegExp(rejectedValue));

  const currentSnapshot = { ...snapshot, observedAt: new Date().toISOString() };
  const accepted = await object.fetch(
    new Request("https://live.example/api/steward/live", {
      method: "POST",
      headers: {
        authorization: "Bearer write-token",
        "content-type": "application/json; charset=utf-8",
      },
      body: JSON.stringify(currentSnapshot),
    }),
  );
  assert.equal(accepted.status, 200);
  assert.equal(messages.length, 1);
  assert.deepEqual(JSON.parse(messages[0]), await accepted.json());

  const current = await object.fetch(new Request("https://live.example/api/steward/live"));
  assert.equal(current.status, 200);
  assert.deepEqual(Object.keys(await current.json()).sort(), [...Object.keys(snapshot), "availability"].sort());

  const older = await object.fetch(
    new Request("https://live.example/api/steward/live", {
      method: "POST",
      headers: {
        authorization: "Bearer write-token",
        "content-type": "application/json",
      },
      body: JSON.stringify({ ...currentSnapshot, observedAt: "2026-06-12T10:20:30Z" }),
    }),
  );
  assert.equal(older.status, 409);
  assert.deepEqual(await older.json(), { error: "stale_update" });
});

test("updates reject invalid types and bodies larger than 16 KiB", async () => {
  const { object } = durable();
  const wrongType = await object.fetch(
    new Request("https://live.example/api/steward/live", {
      method: "POST",
      headers: { authorization: "Bearer write-token", "content-type": "text/plain" },
      body: "{}",
    }),
  );
  assert.equal(wrongType.status, 415);

  const oversized = await object.fetch(
    new Request("https://live.example/api/steward/live", {
      method: "POST",
      headers: { authorization: "Bearer write-token", "content-type": "application/json" },
      body: "x".repeat(16 * 1024 + 1),
    }),
  );
  assert.equal(oversized.status, 413);
  assert.deepEqual(await oversized.json(), { error: "payload_too_large" });

  const future = await object.fetch(
    new Request("https://live.example/api/steward/live", {
      method: "POST",
      headers: { authorization: "Bearer write-token", "content-type": "application/json" },
      body: JSON.stringify({ ...snapshot, observedAt: "9999-01-01T00:00:00Z" }),
    }),
  );
  assert.equal(future.status, 400);
  assert.deepEqual(await future.json(), { error: "invalid_payload" });
});

test("gateway always selects the global Durable Object", async () => {
  const names = [];
  const response = await worker.fetch(new Request("https://live.example/api/steward/live"), {
    LIVE_STATE: {
      idFromName(name) {
        names.push(name);
        return "global-id";
      },
      get(id) {
        assert.equal(id, "global-id");
        return { fetch: () => new Response("ok") };
      },
    },
  });
  assert.equal(await response.text(), "ok");
  assert.deepEqual(names, ["global"]);
});

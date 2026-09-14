import assert from "node:assert/strict";
import Module, { createRequire } from "node:module";
import { test } from "node:test";
import { dirname, resolve } from "node:path";

import example from "../../examples/steward-live-snapshot.json";
import { validateStewardLiveSnapshot } from "../../lib/steward-live/schema";

type ReaderModule = typeof import("../../lib/steward-live/reader");
const requireForTest = createRequire(resolve(process.cwd(), "tests/steward-archive/live-state.test.ts"));
const runtimeModule = Module as unknown as { _resolveFilename: (request: string, parent?: unknown, isMain?: boolean, options?: unknown) => string };

function loadReader(): ReaderModule {
  const empty = resolve(dirname(requireForTest.resolve("next/package.json")), "dist/compiled/server-only/empty.js");
  const previous = runtimeModule._resolveFilename;
  runtimeModule._resolveFilename = function (request, parent, isMain, options) {
    if (request === "server-only") return empty;
    return previous.call(this, request, parent, isMain, options);
  };
  try { return requireForTest(resolve(process.cwd(), "lib/steward-live/reader.ts")) as ReaderModule; }
  finally { runtimeModule._resolveFilename = previous; }
}

const { parseStewardLiveSnapshotUrl, readStewardLiveSnapshot, StewardLiveReadError } = loadReader();

function response(value: unknown, init: ResponseInit = {}) {
  return new Response(JSON.stringify(value), { status: 200, headers: { "content-type": "application/json", ...init.headers }, ...init });
}

function invalid(value: unknown) {
  assert.throws(() => validateStewardLiveSnapshot(value), /invalid Steward live snapshot/);
}

test("live snapshot example passes the exact closed boundary", () => {
  assert.deepEqual(validateStewardLiveSnapshot(example), example);
  invalid({ ...example, extra: true });
  invalid({ ...example, daemon: { ...example.daemon, extra: true } });
  invalid({ ...example, schemaVersion: "1.1" });
  invalid({ ...example, observedAt: "2026-02-31T00:00:00Z" });
  invalid({ ...example, observedAt: "2026-09-14T11:00:00+00:00" });
  invalid({ ...example, staleAfterSeconds: 29 });
  invalid({ ...example, tasks: { active: Number.MAX_SAFE_INTEGER + 1, queued: 0 } });
  invalid({ ...example, planning: { state: "running" } });
});

test("live URL config is independent, server-only, and HTTPS", () => {
  assert.equal(parseStewardLiveSnapshotUrl({ COQUIC_STEWARD_LIVE_SNAPSHOT_URL: " https://live.example.test/state?public=1 " }), "https://live.example.test/state?public=1");
  for (const value of [undefined, "", "http://live.example.test/state", "https://user:pass@live.example.test/state", "https://live.example.test/state#fragment", "not a url"]) {
    assert.throws(() => parseStewardLiveSnapshotUrl({ COQUIC_STEWARD_LIVE_SNAPSHOT_URL: value }), StewardLiveReadError);
  }
});

test("reader performs one bounded no-store request and validates the response", async () => {
  const calls: Array<{ input: string | URL | Request; init?: RequestInit }> = [];
  const result = await readStewardLiveSnapshot({
    env: { COQUIC_STEWARD_LIVE_SNAPSHOT_URL: "https://live.example.test/state" },
    fetch: async (input, init) => { calls.push({ input, init }); return response(example); },
  });
  assert.deepEqual(result, example);
  assert.equal(calls.length, 1);
  assert.equal(calls[0]?.input, "https://live.example.test/state");
  assert.equal(calls[0]?.init?.method, "GET");
  assert.equal(calls[0]?.init?.cache, "no-store");
  assert(calls[0]?.init?.signal instanceof AbortSignal);
});

test("reader rejects transport, media, size, and payload failures by category", async () => {
  const env = { COQUIC_STEWARD_LIVE_SNAPSHOT_URL: "https://live.example.test/state" };
  const code = async (fetcher: typeof fetch, expected: ReaderModule["StewardLiveReadError"]["prototype"]["code"]) => {
    await assert.rejects(() => readStewardLiveSnapshot({ env, fetch: fetcher, maxResponseBytes: 64 }), (error: unknown) => error instanceof StewardLiveReadError && error.code === expected);
  };
  await code(async () => response({}, { status: 503 }), "unavailable");
  await code(async () => new Response("{}", { headers: { "content-type": "text/plain" } }), "invalid");
  await code(async () => response(example, { headers: { "content-length": "1000" } }), "invalid");
  await code(async () => new Response(new ReadableStream({
    start(controller) {
      controller.enqueue(new Uint8Array(40));
      controller.enqueue(new Uint8Array(40));
      controller.close();
    },
  }), { headers: { "content-type": "application/json" } }), "invalid");
  await code(async () => response({ ...example, integration: { active: -1, queued: 0 } }), "invalid");
  await code(async () => { throw new DOMException("timed out", "TimeoutError"); }, "timeout");
  await code(async () => { throw new Error("upstream detail"); }, "unavailable");
});

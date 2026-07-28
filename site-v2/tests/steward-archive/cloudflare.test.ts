import assert from "node:assert/strict";
import Module, { createRequire } from "node:module";
import { test } from "node:test";
import { dirname, resolve } from "node:path";

import type { CloudReaderConfig } from "../../lib/steward-archive/cloud-config";
import type { D1ErrorCode } from "../../lib/steward-archive/cloudflare";

type CloudflareModule = typeof import("../../lib/steward-archive/cloudflare");
const requireForTest = createRequire(resolve(process.cwd(), "tests/steward-archive/cloudflare.test.ts"));
const runtimeModule = Module as unknown as { _resolveFilename: (request: string, parent?: unknown, isMain?: boolean, options?: unknown) => string };

function loadCloudflare(): CloudflareModule {
  const empty = resolve(dirname(requireForTest.resolve("next/package.json")), "dist/compiled/server-only/empty.js");
  const previous = runtimeModule._resolveFilename;
  runtimeModule._resolveFilename = function (request, parent, isMain, options) {
    if (request === "server-only") return empty;
    return previous.call(this, request, parent, isMain, options);
  };
  try { return requireForTest(resolve(process.cwd(), "lib/steward-archive/cloudflare.ts")) as CloudflareModule; }
  finally { runtimeModule._resolveFilename = previous; }
}

const { CloudflareD1Client, CloudflareD1Error } = loadCloudflare();
const TOKEN = "token-must-not-leak";
const SQL = "SELECT value FROM records WHERE id = ?";
const PARAMS = ["private-value"] as const;
const config = { accountId: "a".repeat(32), databaseId: "12345678-1234-4abc-8def-1234567890ab", d1ReadToken: TOKEN, publicR2BaseUrl: "https://objects.example.test/" } as CloudReaderConfig;

function envelope(rows: readonly unknown[][] = [[]]) {
  return { success: true, errors: [], result: rows.map((results) => ({ success: true, results, meta: { rows_read: results.length } })) };
}

function response(body: unknown, contentType = "application/json", status = 200) {
  return new Response(typeof body === "string" ? body : JSON.stringify(body), { status, headers: { "content-type": contentType } });
}

async function code(action: () => Promise<unknown>, expected: D1ErrorCode) {
  await assert.rejects(action, (error: unknown) => error instanceof CloudflareD1Error && error.code === expected);
}

test("posts one parameterized no-store query to the fixed endpoint", async () => {
  const calls: { input: string | URL | Request; init?: RequestInit }[] = [];
  const client = new CloudflareD1Client(config, {
    fetch: async (input, init) => { calls.push({ input, init }); return response(envelope([[{ value: 7 }]])); },
  });
  const result = await client.query(SQL, PARAMS);
  assert.deepEqual(result.result[0]?.results, [{ value: 7 }]);
  assert.equal(calls.length, 1);
  const call = calls[0]!;
  assert.equal(call.input, "https://api.cloudflare.com/client/v4/accounts/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/d1/database/12345678-1234-4abc-8def-1234567890ab/query");
  assert.equal(call.init?.method, "POST");
  assert.equal(call.init?.cache, "no-store");
  assert.equal((call.init?.headers as Record<string, string>).Authorization, `Bearer ${TOKEN}`);
  assert.equal((call.init?.headers as Record<string, string>)["Content-Type"], "application/json");
  assert.deepEqual(JSON.parse(String(call.init?.body)), { sql: SQL, params: PARAMS });
  assert(call.init?.signal instanceof AbortSignal);
});

test("accepts empty, populated, and multiple result sets within bounds", async () => {
  const client = new CloudflareD1Client(config, { fetch: async () => response(envelope([[], [{ id: 1 }], [{ id: 2 }]])) });
  const result = await client.query("SELECT 1", []);
  assert.equal(result.result.length, 3);
  assert.deepEqual(result.result[1]?.meta, { rows_read: 1 });
  assert.deepEqual(result.result[2]?.results, [{ id: 2 }]);
});

test("maps HTTP, envelope, content, JSON, and network failures without diagnostics", async () => {
  for (const [status, expected] of [[401, "unauthorized"], [403, "unauthorized"], [429, "rate-limited"], [500, "server-error"], [418, "http-error"]] as const) {
    await code(() => new CloudflareD1Client(config, { fetch: async () => response("hostile body", "text/plain", status) }).query(SQL, PARAMS), expected);
  }
  await code(() => new CloudflareD1Client(config, { fetch: async () => response("not json") }).query(SQL, PARAMS), "malformed");
  await code(() => new CloudflareD1Client(config, { fetch: async () => response("{}") }).query(SQL, PARAMS), "malformed");
  await code(() => new CloudflareD1Client(config, { fetch: async () => { throw new Error(`${TOKEN} ${SQL} ${PARAMS[0]}`); } }).query(SQL, PARAMS), "network-error");
  await assert.rejects(
    () => new CloudflareD1Client(config, { fetch: async () => response({ success: false, errors: [{ message: `${TOKEN} ${SQL}` }], result: [] }) }).query(SQL, PARAMS),
    (error: unknown) => error instanceof CloudflareD1Error && error.code === "provider-error" && !String(error).includes(TOKEN) && !String(error).includes(SQL),
  );
});

test("enforces response-byte, result-set, and row ceilings", async () => {
  await code(() => new CloudflareD1Client(config, { maxResponseBytes: 4, fetch: async () => response(envelope()) }).query("SELECT 1"), "response-too-large");
  await code(() => new CloudflareD1Client(config, { maxResultSets: 1, fetch: async () => response(envelope([[], []])) }).query("SELECT 1"), "result-set-limit");
  await code(() => new CloudflareD1Client(config, { maxRows: 1, fetch: async () => response(envelope([[{ a: 1 }, { a: 2 }]])) }).query("SELECT 1"), "row-limit");
});

test("aborts timed out work and always clears its timer", async () => {
  let fire: (() => void) | undefined;
  let cleared = 0;
  let aborted = 0;
  class TestController { readonly signal = new AbortController().signal; abort() { aborted += 1; } }
  const client = new CloudflareD1Client(config, {
    AbortController: TestController,
    fetch: async () => new Promise<Response>(() => undefined),
    setTimeout: (handler) => { fire = handler; return 1 as unknown as ReturnType<typeof setTimeout>; },
    clearTimeout: () => { cleared += 1; },
  });
  const pending = client.query("SELECT 1");
  await new Promise<void>((resolve) => queueMicrotask(resolve));
  fire!();
  await code(() => pending, "timeout");
  assert.equal(aborted, 1);
  assert.equal(cleared, 1);
});

test("rejects non-scalar parameters before making a request", async () => {
  let calls = 0;
  const client = new CloudflareD1Client(config, { fetch: async () => { calls += 1; return response(envelope()); } });
  await code(() => client.query("SELECT ?", [{ nested: true } as unknown as null]), "invalid-request");
  await code(() => client.query("   "), "invalid-request");
  assert.equal(calls, 0);
});

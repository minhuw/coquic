import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import Module, { createRequire } from "node:module";
import { dirname, resolve } from "node:path";

import { parseCloudResponse, type CloudResponse } from "../lib/steward-archive/cloud-schema";

type CloudRepositoryModule = typeof import("../lib/steward-archive/cloud-repository");
const requireForTest = createRequire(import.meta.url);
const runtimeModule = Module as unknown as { _resolveFilename: (request: string, parent?: unknown, isMain?: boolean, options?: unknown) => string };
let cloudRepository: CloudRepositoryModule;

function loadCloudRepository(): CloudRepositoryModule {
  const empty = resolve(dirname(requireForTest.resolve("next/package.json")), "dist/compiled/server-only/empty.js");
  const previous = runtimeModule._resolveFilename;
  runtimeModule._resolveFilename = function (request, parent, isMain, options) {
    if (request === "server-only") return empty;
    return previous.call(this, request, parent, isMain, options);
  };
  try {
    return requireForTest(resolve(process.cwd(), "lib/steward-archive/cloud-repository.ts")) as CloudRepositoryModule;
  } finally {
    runtimeModule._resolveFilename = previous;
  }
}

type Fixture = {
  readonly data: {
    readonly task: {
      readonly taskId: string;
      readonly title: string;
      readonly lifecycleState: "active" | "completed" | "failed" | "cancelled";
      readonly createdAt: string;
      readonly completedAt: string | null;
      readonly pipelineId: string | null;
      readonly completedRunId: string | null;
      readonly eventCount: number;
      readonly artifactCount: number;
      readonly disclosure: { readonly redactionApplied: boolean; readonly originalRetained: boolean };
    };
  };
};

type TaskRow = Record<string, unknown>;
type Scenario = {
  readonly rows: readonly TaskRow[];
  readonly statusRows: readonly TaskRow[];
  readonly activeRows: readonly TaskRow[];
  readonly historyRows: readonly TaskRow[];
  readonly mode?: "rate-limited" | "outage" | "malformed" | "integrity";
};

const ENV_KEYS = [
  "CLOUDFLARE_ACCOUNT_ID",
  "COQUIC_STEWARD_D1_DATABASE_ID",
  "COQUIC_STEWARD_D1_READ_TOKEN",
  "COQUIC_STEWARD_PUBLIC_R2_BASE_URL",
] as const;
const VALID_ENV: Record<(typeof ENV_KEYS)[number], string> = {
  CLOUDFLARE_ACCOUNT_ID: "a".repeat(32),
  COQUIC_STEWARD_D1_DATABASE_ID: "12345678-1234-4abc-8def-1234567890ab",
  COQUIC_STEWARD_D1_READ_TOKEN: "route-harness-token",
  COQUIC_STEWARD_PUBLIC_R2_BASE_URL: "https://objects.example.test/public/",
};
const PUBLICATION_ID = "publication-harness";
const EXPOSED_AT = "2026-07-28T00:00:02Z";

function d1Envelope(rows: readonly TaskRow[]): Response {
  return new Response(JSON.stringify({
    success: true,
    errors: [],
    result: [{ success: true, results: rows, meta: {} }],
  }), { status: 200, headers: { "content-type": "application/json" } });
}

function dataResponse(payload: CloudResponse): Extract<CloudResponse, { data: unknown }> {
  assert("data" in payload);
  return payload;
}

function problemResponse(payload: CloudResponse): Extract<CloudResponse, { problem: unknown }> {
  assert("problem" in payload);
  return payload;
}

function publicContract(taskId: string, runId: string, updatedAt: string): TaskRow {
  return {
    head_updated_at: updatedAt,
    head_state: "visible",
    publication_id: PUBLICATION_ID,
    generation_task_id: taskId,
    generation_run_id: runId,
    generation_metadata_digest: "a".repeat(64),
    generation_idempotency_key: `harness-${taskId}`,
    generation_state: "visible",
    generation_expected_task_count: 1,
    generation_expected_pipeline_count: 1,
    generation_expected_run_count: 1,
    generation_expected_event_count: 2,
    generation_expected_artifact_count: 3,
    generation_created_at: "2026-07-28T00:00:00Z",
    generation_exposed_at: EXPOSED_AT,
    task_id: taskId,
  };
}

function taskRow(fixture: Fixture["data"]["task"], updatedAt: string): TaskRow {
  const runId = fixture.completedRunId ?? `${fixture.taskId}-run`;
  const pipelineId = fixture.pipelineId ?? `${fixture.taskId}-pipeline`;
  return {
    ...publicContract(fixture.taskId, runId, updatedAt),
    title: fixture.title,
    lifecycle_state: fixture.lifecycleState,
    created_at: fixture.createdAt,
    completed_at: fixture.completedAt,
    expected_event_count: fixture.eventCount,
    expected_artifact_count: fixture.artifactCount,
    event_count: fixture.eventCount,
    artifact_count: fixture.artifactCount,
    pipeline_id: pipelineId,
    run_id: runId,
    run_state: "completed",
    redaction_applied_min: fixture.disclosure.redactionApplied ? 1 : 0,
    redaction_applied_max: fixture.disclosure.redactionApplied ? 1 : 0,
    original_retained_min: fixture.disclosure.originalRetained ? 1 : 0,
    original_retained_max: fixture.disclosure.originalRetained ? 1 : 0,
  };
}

function statusRow(row: TaskRow): TaskRow {
  const keys = [
    "head_updated_at", "head_state", "publication_id", "generation_task_id", "generation_run_id",
    "generation_metadata_digest", "generation_idempotency_key", "generation_state", "generation_expected_task_count",
    "generation_expected_pipeline_count", "generation_expected_run_count", "generation_expected_event_count",
    "generation_expected_artifact_count", "generation_created_at", "generation_exposed_at", "task_id",
  ];
  return Object.fromEntries(keys.map((key) => [key, row[key]]));
}

function compareRows(left: TaskRow, right: TaskRow): number {
  const leftTime = String(left.head_updated_at);
  const rightTime = String(right.head_updated_at);
  if (leftTime !== rightTime) return leftTime > rightTime ? -1 : 1;
  const leftId = String(left.task_id);
  const rightId = String(right.task_id);
  return leftId === rightId ? 0 : leftId > rightId ? -1 : 1;
}

function scenario(activeRows: readonly TaskRow[], historyRows: readonly TaskRow[], mode?: Scenario["mode"]): Scenario {
  const rows = [...activeRows, ...historyRows];
  const status = [...rows].sort((left, right) => {
    const leftId = String(left.task_id);
    const rightId = String(right.task_id);
    return leftId === rightId ? 0 : leftId > rightId ? -1 : 1;
  });
  return { rows, statusRows: status.map(statusRow), activeRows: [...activeRows].sort(compareRows), historyRows: [...historyRows].sort(compareRows), mode };
}

function pageRows(rows: readonly TaskRow[], statement: string, params: readonly unknown[]): readonly TaskRow[] {
  const limit = Number(params.at(-1));
  if (statement === cloudRepository.ACTIVE_PAGE_FIRST_STATEMENT || statement === cloudRepository.HISTORY_PAGE_FIRST_STATEMENT) return rows.slice(0, limit);
  const updatedAt = String(params[0]);
  const taskId = String(params[2]);
  if (statement.includes("h.updated_at < ?")) {
    return rows.filter((row) => String(row.head_updated_at) < updatedAt || (String(row.head_updated_at) === updatedAt && String(row.task_id) < taskId)).slice(0, limit);
  }
  return [...rows]
    .filter((row) => String(row.head_updated_at) > updatedAt || (String(row.head_updated_at) === updatedAt && String(row.task_id) > taskId))
    .sort((left, right) => {
      const compared = compareRows(left, right);
      return compared === 0 ? 0 : -compared;
    })
    .slice(0, limit);
}

function fakeFetch(scenarioValue: Scenario, calls: { count: number; urls: string[] }) {
  return async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    calls.count += 1;
    const url = String(input);
    calls.urls.push(url);
    assert.match(url, /^https:\/\/api\.cloudflare\.com\/client\/v4\//);
    if (scenarioValue.mode === "rate-limited") return new Response("rate limited", { status: 429 });
    if (scenarioValue.mode === "outage") throw new Error("route-harness-secret outage");
    const body = JSON.parse(String(init?.body)) as { readonly sql: string; readonly params: readonly unknown[] };
    const statement = body.sql;
    const params = body.params;
    if (scenarioValue.mode === "malformed") return new Response(JSON.stringify({ success: true, errors: [], result: "malformed" }), { status: 200, headers: { "content-type": "application/json" } });
    if (scenarioValue.mode === "integrity" && statement === cloudRepository.STATUS_VALIDATION_STATEMENT) {
      const malformed = { ...scenarioValue.statusRows[0], credential_path: "route-harness-secret" };
      return d1Envelope([malformed]);
    }
    if (statement === cloudRepository.STATUS_STATEMENT) {
      if (scenarioValue.statusRows.length === 0) return d1Envelope([]);
      return d1Envelope([{ task_count: scenarioValue.statusRows.length, latest_publication_at: EXPOSED_AT, latest_publication_id: PUBLICATION_ID }]);
    }
    if (statement === cloudRepository.STATUS_VALIDATION_STATEMENT) return d1Envelope(scenarioValue.statusRows.slice(0, Number(params[0])));
    if (statement === cloudRepository.STATUS_VALIDATION_NEXT_STATEMENT) return d1Envelope([]);
    const rows = statement.includes("lifecycle_state = 'active'") || statement === cloudRepository.ACTIVE_COUNT_STATEMENT || statement === cloudRepository.ACTIVE_CURSOR_STATEMENT
      ? scenarioValue.activeRows
      : scenarioValue.historyRows;
    if (statement === cloudRepository.ACTIVE_COUNT_STATEMENT || statement === cloudRepository.HISTORY_COUNT_STATEMENT) return d1Envelope([{ task_count: rows.length }]);
    if (statement === cloudRepository.ACTIVE_CURSOR_STATEMENT || statement === cloudRepository.HISTORY_CURSOR_STATEMENT) {
      const found = rows.find((row) => row.head_updated_at === params[0] && row.task_id === params[1]);
      return d1Envelope(found ? [statusRow(found)] : []);
    }
    if (statement === cloudRepository.ACTIVE_PAGE_FIRST_STATEMENT || statement === cloudRepository.HISTORY_PAGE_FIRST_STATEMENT) return d1Envelope(pageRows(rows, statement, params));
    if (statement === cloudRepository.ACTIVE_PAGE_NEXT_STATEMENT || statement === cloudRepository.HISTORY_PAGE_NEXT_STATEMENT) return d1Envelope(pageRows(rows, statement, params));
    if (statement === cloudRepository.ACTIVE_PAGE_PREVIOUS_STATEMENT || statement === cloudRepository.HISTORY_PAGE_PREVIOUS_STATEMENT) return d1Envelope(pageRows(rows, statement, params));
    throw new Error("unexpected route harness query");
  };
}

async function fixture(path: string): Promise<Fixture> {
  return JSON.parse(await readFile(new URL(path, import.meta.url), "utf8")) as Fixture;
}

async function main() {
  cloudRepository = loadCloudRepository();
  const activeFixture = await fixture("../examples/steward-cloud/active-after-planning.json");
  const historyFixture = await fixture("../examples/steward-cloud/redacted-publication.json");
  const activeSecond = { ...activeFixture.data.task, taskId: "task-active-second", title: "Second active publication" };
  const activeRows = [
    taskRow(activeFixture.data.task, "2026-07-28T00:00:03Z"),
    taskRow(activeSecond, "2026-07-28T00:00:02Z"),
  ];
  const historyRows = [taskRow(historyFixture.data.task, "2026-07-28T00:00:01Z")];
  const { GET: getStatus } = await import("../app/api/steward/status/route");
  const { GET: getTasks } = await import("../app/api/steward/tasks/route");
  const originalFetch = globalThis.fetch;
  const originalEnvironment = Object.fromEntries(ENV_KEYS.map((key) => [key, process.env[key]]));
  const outputs: string[] = [];

  async function runCase(name: string, value: Scenario, action: () => Promise<void>, environment: Record<string, string | undefined> = VALID_ENV) {
    const calls = { count: 0, urls: [] as string[] };
    try {
      for (const key of ENV_KEYS) {
        const next = environment[key];
        if (next === undefined) delete process.env[key];
        else process.env[key] = next;
      }
      globalThis.fetch = fakeFetch(value, calls) as typeof fetch;
      cloudRepository.resetCloudRepository();
      await action();
      outputs.push(`${name}: pass (${calls.count} mocked requests)`);
    } finally {
      cloudRepository.resetCloudRepository();
      globalThis.fetch = originalFetch;
      for (const key of ENV_KEYS) {
        const previous = originalEnvironment[key];
        if (previous === undefined) delete process.env[key];
        else process.env[key] = previous;
      }
    }
  }

  await runCase("empty status", scenario([], []), async () => {
    const response = await getStatus();
    assert.equal(response.status, 200);
    const payload = dataResponse(parseCloudResponse(await response.text()));
    assert.equal(payload.schemaVersion, "3.0");
    assert("state" in payload.data);
    assert.equal(payload.data.state, "empty");
  });

  await runCase("ready status", scenario(activeRows, historyRows), async () => {
    const response = await getStatus();
    assert.equal(response.status, 200);
    const payload = dataResponse(parseCloudResponse(await response.text()));
    assert("state" in payload.data);
    assert.equal(payload.data.state, "available");
    assert.equal(payload.data.taskCount, 3);
    assert.equal(payload.data.latestPublicationAt, EXPOSED_AT);
  });

  await runCase("active page", scenario(activeRows, historyRows), async () => {
    const response = await getTasks(new Request("https://site.test/api/steward/tasks?scope=active&limit=1"));
    assert.equal(response.status, 200);
    const payload = dataResponse(parseCloudResponse(await response.text()));
    assert.equal(payload.schemaVersion, "3.0");
    if (!("items" in payload.data)) throw new Error("expected task page");
    assert.equal(payload.data.items.length, 1);
    assert.equal(payload.data.items[0]?.taskId, "task-active");
    assert.equal(payload.data.pagination.pageSize, 1);
    assert(response.headers.get("X-Steward-Next-Cursor"));
    for (const excluded of ["task-hidden", "task-staged"]) assert(!JSON.stringify(payload).includes(excluded));
    assert(!JSON.stringify(payload).includes("private"));
  });

  const first = await (async () => {
    const calls = { count: 0, urls: [] as string[] };
    globalThis.fetch = fakeFetch(scenario(activeRows, historyRows), calls) as typeof fetch;
    for (const key of ENV_KEYS) process.env[key] = VALID_ENV[key];
    cloudRepository.resetCloudRepository();
    try { return await getTasks(new Request("https://site.test/api/steward/tasks?scope=active&limit=1")); }
    finally { cloudRepository.resetCloudRepository(); globalThis.fetch = originalFetch; for (const key of ENV_KEYS) { const previous = originalEnvironment[key]; if (previous === undefined) delete process.env[key]; else process.env[key] = previous; } }
  })();
  const nextCursor = first.headers.get("X-Steward-Next-Cursor");
  assert(nextCursor);

  await runCase("forward cursor", scenario(activeRows, historyRows), async () => {
    const response = await getTasks(new Request(`https://site.test/api/steward/tasks?scope=active&limit=1&cursor=${encodeURIComponent(nextCursor)}`));
    assert.equal(response.status, 200);
    const payload = dataResponse(parseCloudResponse(await response.text()));
    if (!("items" in payload.data)) throw new Error("expected task page");
    assert.deepEqual(payload.data.items.map((item) => item.taskId), ["task-active-second"]);
    assert(response.headers.get("X-Steward-Previous-Cursor"));
  });

  await runCase("backward cursor", scenario(activeRows, historyRows), async () => {
    const response = await getTasks(new Request(`https://site.test/api/steward/tasks?scope=active&limit=1&cursor=${encodeURIComponent(nextCursor)}`));
    const previous = response.headers.get("X-Steward-Previous-Cursor");
    assert(previous);
    const back = await getTasks(new Request(`https://site.test/api/steward/tasks?scope=active&limit=1&cursor=${encodeURIComponent(previous)}`));
    assert.equal(back.status, 200);
    const payload = dataResponse(parseCloudResponse(await back.text()));
    if (!("items" in payload.data)) throw new Error("expected task page");
    assert.deepEqual(payload.data.items.map((item) => item.taskId), ["task-active"]);
  });

  await runCase("history page and clamped limit", scenario(activeRows, historyRows), async () => {
    const response = await getTasks(new Request("https://site.test/api/steward/tasks?limit=999"));
    assert.equal(response.status, 200);
    const payload = dataResponse(parseCloudResponse(await response.text()));
    if (!("items" in payload.data)) throw new Error("expected task page");
    assert.deepEqual(payload.data.items.map((item) => item.taskId), ["task-redacted"]);
    assert.equal(payload.data.pagination.pageSize, 50);
  });

  await runCase("invalid input", scenario(activeRows, historyRows), async () => {
    const response = await getTasks(new Request("https://site.test/api/steward/tasks?scope=unknown&limit=bad"));
    assert.equal(response.status, 400);
    const payload = problemResponse(parseCloudResponse(await response.text()));
    assert.equal(payload.problem.code, "INVALID_REQUEST");
  });

  await runCase("stale cursor", scenario(activeRows, historyRows), async () => {
    const cursor = cloudRepository.encodePublicationCursor({ query: "tasks-active", publicationId: "publication-old", sort: ["2026-07-28T00:00:03Z", "task-active", "next"] });
    const response = await getTasks(new Request(`https://site.test/api/steward/tasks?scope=active&cursor=${encodeURIComponent(cursor)}`));
    assert.equal(response.status, 409);
    const payload = problemResponse(parseCloudResponse(await response.text()));
    assert.equal(payload.problem.code, "STALE_CURSOR");
  });

  await runCase("rate limited", { ...scenario([], []), mode: "rate-limited" }, async () => {
    const response = await getStatus();
    assert.equal(response.status, 429);
    const payload = problemResponse(parseCloudResponse(await response.text()));
    assert.equal(payload.problem.code, "RATE_LIMITED");
    assert(!JSON.stringify(payload).includes("route-harness-secret"));
  });

  await runCase("outage", { ...scenario([], []), mode: "outage" }, async () => {
    const response = await getStatus();
    assert.equal(response.status, 503);
    const payload = problemResponse(parseCloudResponse(await response.text()));
    assert.equal(payload.problem.code, "UNAVAILABLE");
    assert(!JSON.stringify(payload).includes("route-harness-secret"));
  });

  await runCase("malformed D1", { ...scenario([], []), mode: "malformed" }, async () => {
    const response = await getStatus();
    assert.equal(response.status, 503);
    const payload = problemResponse(parseCloudResponse(await response.text()));
    assert.equal(payload.problem.code, "UNAVAILABLE");
  });

  await runCase("integrity failure", { ...scenario(activeRows, historyRows), mode: "integrity" }, async () => {
    const response = await getStatus();
    assert.equal(response.status, 503);
    const payload = problemResponse(parseCloudResponse(await response.text()));
    assert.equal(payload.problem.code, "INTEGRITY_FAILURE");
    assert(!JSON.stringify(payload).includes("route-harness-secret"));
  });

  await runCase("missing configuration", scenario([], []), async () => {
    const response = await getStatus();
    assert.equal(response.status, 503);
    const payload = problemResponse(parseCloudResponse(await response.text()));
    assert.equal(payload.problem.code, "MISCONFIGURED");
  }, {
    CLOUDFLARE_ACCOUNT_ID: undefined,
    COQUIC_STEWARD_D1_DATABASE_ID: undefined,
    COQUIC_STEWARD_D1_READ_TOKEN: undefined,
    COQUIC_STEWARD_PUBLIC_R2_BASE_URL: undefined,
  });

  process.stdout.write(`${outputs.join("\n")}\nSteward cloud route harness passed with no external requests\n`);
}

void main().catch((error: unknown) => {
  process.stderr.write(`${error instanceof Error ? error.stack ?? error.message : String(error)}\n`);
  process.exitCode = 1;
});

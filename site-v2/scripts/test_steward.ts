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
type DetailScenario = {
  readonly task: TaskRow | null;
  readonly pipelines: readonly TaskRow[];
  readonly runs: readonly TaskRow[];
  readonly events: readonly TaskRow[];
  readonly artifacts: readonly TaskRow[];
};
type Scenario = {
  readonly rows: readonly TaskRow[];
  readonly statusRows: readonly TaskRow[];
  readonly activeRows: readonly TaskRow[];
  readonly historyRows: readonly TaskRow[];
  readonly mode?: "rate-limited" | "outage" | "malformed" | "integrity" | "unauthorized" | "server-error";
  readonly detail?: DetailScenario;
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
const DETAIL_TASK_ID = "task-detail";
const DETAIL_PUBLICATION_ID = "publication-detail";
const DETAIL_RUN_ID = "run-detail";
const DETAIL_PIPELINE_ID = "pipeline-detail";
const DETAIL_DIGEST = "b".repeat(64);
const DETAIL_PUBLIC_KEY = `v1/tasks/${DETAIL_TASK_ID}/objects/sha256/bb/${DETAIL_DIGEST}`;

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

function detailScenario(options: {
  lifecycleState?: "active" | "completed";
  availability?: "available" | "unavailable";
  redactionApplied?: boolean;
  originalRetained?: boolean;
} = {}): DetailScenario {
  const lifecycleState = options.lifecycleState ?? "completed";
  const completedAt = lifecycleState === "active" ? null : "2026-07-28T00:00:03Z";
  const task: TaskRow = {
    head_updated_at: "2026-07-28T00:00:04Z",
    head_state: "visible",
    publication_id: DETAIL_PUBLICATION_ID,
    generation_task_id: DETAIL_TASK_ID,
    generation_run_id: DETAIL_RUN_ID,
    generation_metadata_digest: "a".repeat(64),
    generation_idempotency_key: "harness-detail",
    generation_state: "visible",
    generation_expected_task_count: 1,
    generation_expected_pipeline_count: 1,
    generation_expected_run_count: 1,
    generation_expected_event_count: 2,
    generation_expected_artifact_count: 1,
    generation_created_at: "2026-07-28T00:00:00Z",
    generation_exposed_at: EXPOSED_AT,
    task_id: DETAIL_TASK_ID,
    title: "Detail task",
    lifecycle_state: lifecycleState,
    created_at: "2026-07-28T00:00:00Z",
    completed_at: completedAt,
  };
  return {
    task,
    pipelines: [{
      publication_id: DETAIL_PUBLICATION_ID,
      pipeline_id: DETAIL_PIPELINE_ID,
      task_id: DETAIL_TASK_ID,
      name: "Detail pipeline",
      created_at: "2026-07-28T00:00:00Z",
    }],
    runs: [{
      publication_id: DETAIL_PUBLICATION_ID,
      run_id: DETAIL_RUN_ID,
      task_id: DETAIL_TASK_ID,
      pipeline_id: DETAIL_PIPELINE_ID,
      role: "planning",
      run_state: "completed",
      started_at: "2026-07-28T00:00:00Z",
      completed_at: "2026-07-28T00:00:01Z",
      duration_ms: 1_000,
      atif_digest: DETAIL_DIGEST,
    }],
    events: [
      { publication_id: DETAIL_PUBLICATION_ID, task_id: DETAIL_TASK_ID, sequence: 1, event_type: "started", occurred_at: "2026-07-28T00:00:00Z", summary: "Started" },
      { publication_id: DETAIL_PUBLICATION_ID, task_id: DETAIL_TASK_ID, sequence: 2, event_type: "completed", occurred_at: "2026-07-28T00:00:01Z", summary: "Completed" },
    ],
    artifacts: [{
      publication_id: DETAIL_PUBLICATION_ID,
      artifact_id: "artifact-atif",
      task_id: DETAIL_TASK_ID,
      run_id: DETAIL_RUN_ID,
      logical_path: "runs/run-detail/trajectory.json",
      public_key: DETAIL_PUBLIC_KEY,
      media_type: "application/json",
      byte_size: 128,
      sha256: DETAIL_DIGEST,
      availability: options.availability ?? "available",
      redaction_applied: options.redactionApplied ? 1 : 0,
      original_retained: options.originalRetained === false ? 0 : 1,
    }],
  };
}

function compareRows(left: TaskRow, right: TaskRow): number {
  const leftTime = String(left.head_updated_at);
  const rightTime = String(right.head_updated_at);
  if (leftTime !== rightTime) return leftTime > rightTime ? -1 : 1;
  const leftId = String(left.task_id);
  const rightId = String(right.task_id);
  return leftId === rightId ? 0 : leftId > rightId ? -1 : 1;
}

function visibleRow(row: TaskRow): boolean {
  return row.head_state === "visible" && row.generation_state === "visible";
}

const DETAIL_TASK_COLUMNS = [
  "head_updated_at", "head_state", "publication_id", "generation_task_id", "generation_run_id", "generation_metadata_digest",
  "generation_idempotency_key", "generation_state", "generation_expected_task_count", "generation_expected_pipeline_count",
  "generation_expected_run_count", "generation_expected_event_count", "generation_expected_artifact_count", "generation_created_at",
  "generation_exposed_at", "task_id", "title", "lifecycle_state", "created_at", "completed_at",
] as const;

function detailTaskRow(row: TaskRow): TaskRow {
  return Object.fromEntries(DETAIL_TASK_COLUMNS.map((column) => [column, row[column]]));
}

function detailQueryVisibility(statement: string): { readonly head: boolean; readonly generation: boolean } {
  return {
    head: /h\.state\s*=\s*'visible'/.test(statement),
    generation: /p\.state\s*=\s*'visible'/.test(statement) && /p\.exposed_at\s+IS\s+NOT\s+NULL/.test(statement),
  };
}

function scenario(
  activeRows: readonly TaskRow[],
  historyRows: readonly TaskRow[],
  mode?: Scenario["mode"],
  candidates: readonly TaskRow[] = [],
  detail?: DetailScenario,
): Scenario {
  const rows = [...activeRows, ...historyRows, ...candidates];
  const allActiveRows = [...activeRows, ...candidates.filter((row) => row.lifecycle_state === "active")];
  const allHistoryRows = [...historyRows, ...candidates.filter((row) => row.lifecycle_state !== "active")];
  const status = rows.filter(visibleRow).sort((left, right) => {
    const leftId = String(left.task_id);
    const rightId = String(right.task_id);
    return leftId === rightId ? 0 : leftId > rightId ? -1 : 1;
  });
  return {
    rows,
    statusRows: status.map(statusRow),
    activeRows: allActiveRows.sort(compareRows),
    historyRows: allHistoryRows.sort(compareRows),
    mode,
    detail,
  };
}

function pageRows(rows: readonly TaskRow[], statement: string, params: readonly unknown[]): readonly TaskRow[] {
  const visibleRows = rows.filter(visibleRow);
  const limit = Number(params.at(-1));
  if (statement === cloudRepository.ACTIVE_PAGE_FIRST_STATEMENT || statement === cloudRepository.HISTORY_PAGE_FIRST_STATEMENT) return visibleRows.slice(0, limit);
  const updatedAt = String(params[0]);
  const taskId = String(params[2]);
  if (statement.includes("h.updated_at < ?")) {
    return visibleRows.filter((row) => String(row.head_updated_at) < updatedAt || (String(row.head_updated_at) === updatedAt && String(row.task_id) < taskId)).slice(0, limit);
  }
  return [...visibleRows]
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
    if (scenarioValue.mode === "unauthorized") return new Response("unauthorized", { status: 401 });
    if (scenarioValue.mode === "server-error") return new Response("server error", { status: 503 });
    const body = JSON.parse(String(init?.body)) as { readonly sql: string; readonly params: readonly unknown[] };
    const statement = body.sql;
    const params = body.params;
    if (scenarioValue.mode === "malformed") return new Response("{}", { status: 200, headers: { "content-type": "application/json" } });
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
    if (statement === cloudRepository.TASK_DETAIL_STATEMENT) {
      const taskId = String(params[0]);
      const candidate = scenarioValue.rows.find((row) => String(row.task_id) === taskId);
      if (candidate && !visibleRow(candidate)) {
        const visibility = detailQueryVisibility(statement);
        return d1Envelope(
          (candidate.head_state === "hidden" && !visibility.head) || (candidate.generation_state === "staged" && !visibility.generation)
            ? [detailTaskRow(candidate)]
            : [],
        );
      }
      return d1Envelope(scenarioValue.detail?.task?.task_id === taskId ? [scenarioValue.detail.task] : []);
    }
    if (statement === cloudRepository.TASK_DETAIL_PIPELINES_STATEMENT) return d1Envelope(scenarioValue.detail?.pipelines ?? []);
    if (statement === cloudRepository.TASK_DETAIL_RUNS_STATEMENT) return d1Envelope(scenarioValue.detail?.runs ?? []);
    if (statement === cloudRepository.TASK_DETAIL_EVENTS_STATEMENT) return d1Envelope(scenarioValue.detail?.events ?? []);
    if (statement === cloudRepository.TASK_DETAIL_ARTIFACTS_STATEMENT) return d1Envelope(scenarioValue.detail?.artifacts ?? []);
    if (statement === cloudRepository.ARTIFACT_DESCRIPTOR_STATEMENT) {
      const taskId = String(params[0]);
      const logicalPath = String(params[1]);
      return d1Envelope((scenarioValue.detail?.artifacts ?? []).filter((row) => row.task_id === taskId && row.logical_path === logicalPath));
    }
    const rows = statement.includes("lifecycle_state = 'active'") || statement === cloudRepository.ACTIVE_COUNT_STATEMENT || statement === cloudRepository.ACTIVE_CURSOR_STATEMENT
      ? scenarioValue.activeRows
      : scenarioValue.historyRows;
    const visibleRows = rows.filter(visibleRow);
    if (statement === cloudRepository.ACTIVE_COUNT_STATEMENT || statement === cloudRepository.HISTORY_COUNT_STATEMENT) return d1Envelope([{ task_count: visibleRows.length }]);
    if (statement === cloudRepository.ACTIVE_CURSOR_STATEMENT || statement === cloudRepository.HISTORY_CURSOR_STATEMENT) {
      const found = visibleRows.find((row) => row.head_updated_at === params[0] && row.task_id === params[1]);
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
  const hiddenCandidate = {
    ...taskRow(activeFixture.data.task, "2026-07-28T00:00:04Z"),
    task_id: "task-hidden",
    generation_task_id: "task-hidden",
    generation_idempotency_key: "harness-task-hidden",
    head_state: "hidden",
  };
  const stagedCandidate = {
    ...taskRow(historyFixture.data.task, "2026-07-28T00:00:05Z"),
    task_id: "task-staged",
    generation_task_id: "task-staged",
    generation_idempotency_key: "harness-task-staged",
    generation_state: "staged",
  };
  const candidateRows = [hiddenCandidate, stagedCandidate];
  const { GET: getStatus } = await import("../app/api/steward/status/route");
  const { GET: getTasks } = await import("../app/api/steward/tasks/route");
  const { GET: getTaskDetail } = await import("../app/api/steward/tasks/[taskId]/route");
  const { GET: getArtifact } = await import("../app/api/steward/tasks/[taskId]/artifact/route");
  const { GET: getTranscript } = await import("../app/api/steward/tasks/[taskId]/transcript/route");
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

  await runCase("empty status", scenario([], [], undefined, candidateRows), async () => {
    const response = await getStatus();
    assert.equal(response.status, 200);
    const payload = dataResponse(parseCloudResponse(await response.text()));
    assert.equal(payload.schemaVersion, "3.0");
    assert("state" in payload.data);
    assert.equal(payload.data.state, "empty");
  });

  await runCase("ready status", scenario(activeRows, historyRows, undefined, candidateRows), async () => {
    const response = await getStatus();
    assert.equal(response.status, 200);
    const payload = dataResponse(parseCloudResponse(await response.text()));
    assert("state" in payload.data);
    assert.equal(payload.data.state, "available");
    assert.equal(payload.data.taskCount, 3);
    assert.equal(payload.data.latestPublicationAt, EXPOSED_AT);
  });

  await runCase("active page", scenario(activeRows, historyRows, undefined, candidateRows), async () => {
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

  await runCase("empty active page", scenario([], historyRows, undefined, [hiddenCandidate]), async () => {
    const response = await getTasks(new Request("https://site.test/api/steward/tasks?scope=active&limit=10"));
    assert.equal(response.status, 200);
    const payload = dataResponse(parseCloudResponse(await response.text()));
    assert.equal(payload.schemaVersion, "3.0");
    if (!("items" in payload.data)) throw new Error("expected task page");
    assert.deepEqual(payload.data.items, []);
    assert.deepEqual(payload.data.pagination, { page: 1, pageSize: 10, total: 0, hasNextPage: false });
    assert(!JSON.stringify(payload).includes("task-hidden"));
    assert(!response.headers.get("X-Steward-Next-Cursor"));
  });

  await runCase("empty history page", scenario(activeRows, [], undefined, [stagedCandidate]), async () => {
    const response = await getTasks(new Request("https://site.test/api/steward/tasks?scope=history&limit=10"));
    assert.equal(response.status, 200);
    const payload = dataResponse(parseCloudResponse(await response.text()));
    assert.equal(payload.schemaVersion, "3.0");
    if (!("items" in payload.data)) throw new Error("expected task page");
    assert.deepEqual(payload.data.items, []);
    assert.deepEqual(payload.data.pagination, { page: 1, pageSize: 10, total: 0, hasNextPage: false });
    assert(!JSON.stringify(payload).includes("task-staged"));
    assert(!response.headers.get("X-Steward-Next-Cursor"));
  });

  const first = await (async () => {
    const calls = { count: 0, urls: [] as string[] };
    globalThis.fetch = fakeFetch(scenario(activeRows, historyRows, undefined, candidateRows), calls) as typeof fetch;
    for (const key of ENV_KEYS) process.env[key] = VALID_ENV[key];
    cloudRepository.resetCloudRepository();
    try { return await getTasks(new Request("https://site.test/api/steward/tasks?scope=active&limit=1")); }
    finally { cloudRepository.resetCloudRepository(); globalThis.fetch = originalFetch; for (const key of ENV_KEYS) { const previous = originalEnvironment[key]; if (previous === undefined) delete process.env[key]; else process.env[key] = previous; } }
  })();
  const nextCursor = first.headers.get("X-Steward-Next-Cursor");
  assert(nextCursor);

  await runCase("forward cursor", scenario(activeRows, historyRows, undefined, candidateRows), async () => {
    const response = await getTasks(new Request(`https://site.test/api/steward/tasks?scope=active&limit=1&cursor=${encodeURIComponent(nextCursor)}`));
    assert.equal(response.status, 200);
    const payload = dataResponse(parseCloudResponse(await response.text()));
    if (!("items" in payload.data)) throw new Error("expected task page");
    assert.deepEqual(payload.data.items.map((item) => item.taskId), ["task-active-second"]);
    assert(response.headers.get("X-Steward-Previous-Cursor"));
  });

  await runCase("backward cursor", scenario(activeRows, historyRows, undefined, candidateRows), async () => {
    const response = await getTasks(new Request(`https://site.test/api/steward/tasks?scope=active&limit=1&cursor=${encodeURIComponent(nextCursor)}`));
    const previous = response.headers.get("X-Steward-Previous-Cursor");
    assert(previous);
    const back = await getTasks(new Request(`https://site.test/api/steward/tasks?scope=active&limit=1&cursor=${encodeURIComponent(previous)}`));
    assert.equal(back.status, 200);
    const payload = dataResponse(parseCloudResponse(await back.text()));
    if (!("items" in payload.data)) throw new Error("expected task page");
    assert.deepEqual(payload.data.items.map((item) => item.taskId), ["task-active"]);
  });

  await runCase("history page and clamped limit", scenario(activeRows, historyRows, undefined, candidateRows), async () => {
    const response = await getTasks(new Request("https://site.test/api/steward/tasks?limit=999"));
    assert.equal(response.status, 200);
    const payload = dataResponse(parseCloudResponse(await response.text()));
    if (!("items" in payload.data)) throw new Error("expected task page");
    assert.deepEqual(payload.data.items.map((item) => item.taskId), ["task-redacted"]);
    assert.equal(payload.data.pagination.pageSize, 50);
    for (const excluded of ["task-hidden", "task-staged"]) assert(!JSON.stringify(payload).includes(excluded));
  });

  const taskContext = (taskId: string) => ({ params: Promise.resolve({ taskId }) });

  await runCase("clean cloud detail", scenario([], [], undefined, [], detailScenario()), async () => {
    const response = await getTaskDetail(new Request("https://site.test/api/steward/tasks/task-detail"), taskContext(DETAIL_TASK_ID));
    assert.equal(response.status, 200);
    const payload = dataResponse(parseCloudResponse(await response.text()));
    assert.equal(payload.schemaVersion, "3.0");
    if (!("pipelines" in payload.data)) throw new Error("expected task detail");
    assert.equal(payload.data.task.taskId, DETAIL_TASK_ID);
    assert.equal(payload.data.trajectory?.runId, DETAIL_RUN_ID);
    assert.equal(payload.data.trajectory?.artifactId, "artifact-atif");
    assert(!JSON.stringify(payload).includes("private"));
  });

  await runCase("redacted cloud detail", scenario([], [], undefined, [], detailScenario({ redactionApplied: true, originalRetained: false })), async () => {
    const response = await getTaskDetail(new Request("https://site.test/api/steward/tasks/task-detail"), taskContext(DETAIL_TASK_ID));
    assert.equal(response.status, 200);
    const payload = dataResponse(parseCloudResponse(await response.text()));
    if (!("pipelines" in payload.data)) throw new Error("expected task detail");
    assert.equal(payload.data.task.disclosure.redactionApplied, true);
    assert.equal(payload.data.task.disclosure.originalRetained, false);
  });

  await runCase("active-after-planning cloud detail", scenario([], [], undefined, [], detailScenario({ lifecycleState: "active" })), async () => {
    const response = await getTaskDetail(new Request("https://site.test/api/steward/tasks/task-detail"), taskContext(DETAIL_TASK_ID));
    assert.equal(response.status, 200);
    const payload = dataResponse(parseCloudResponse(await response.text()));
    if (!("pipelines" in payload.data)) throw new Error("expected task detail");
    assert.equal(payload.data.task.lifecycleState, "active");
    assert.equal(payload.data.task.completedAt, null);
    assert.equal(payload.data.trajectory?.runId, DETAIL_RUN_ID);
  });

  await runCase("hidden and staged detail exclusion", scenario([], [], undefined, candidateRows), async () => {
    for (const taskId of ["task-hidden", "task-staged"]) {
      const response = await getTaskDetail(new Request(`https://site.test/api/steward/tasks/${taskId}`), taskContext(taskId));
      assert.equal(response.status, 404);
      const payload = problemResponse(parseCloudResponse(await response.text()));
      assert.equal(payload.problem.code, "NOT_FOUND");
      assert(!JSON.stringify(payload).includes(taskId));
    }
  });

  const malformedDetail = detailScenario();
  malformedDetail.task!.credential_path = "route-harness-secret";
  await runCase("malformed detail data", scenario([], [], undefined, [], malformedDetail), async () => {
    const response = await getTaskDetail(new Request("https://site.test/api/steward/tasks/task-detail"), taskContext(DETAIL_TASK_ID));
    assert.equal(response.status, 503);
    const payload = problemResponse(parseCloudResponse(await response.text()));
    assert.equal(payload.problem.code, "INTEGRITY_FAILURE");
    assert(!JSON.stringify(payload).includes("route-harness-secret"));
  });

  const danglingDetail = detailScenario();
  danglingDetail.runs[0]!.pipeline_id = "pipeline-missing";
  await runCase("dangling detail data", scenario([], [], undefined, [], danglingDetail), async () => {
    const response = await getTaskDetail(new Request("https://site.test/api/steward/tasks/task-detail"), taskContext(DETAIL_TASK_ID));
    assert.equal(response.status, 503);
    const payload = problemResponse(parseCloudResponse(await response.text()));
    assert.equal(payload.problem.code, "INTEGRITY_FAILURE");
  });

  await runCase("validated artifact redirect", scenario([], [], undefined, [], detailScenario()), async () => {
    const path = encodeURIComponent("runs/run-detail/trajectory.json");
    const response = await getArtifact(new Request(`https://site.test/api/steward/tasks/task-detail/artifact?path=${path}&url=${encodeURIComponent("https://attacker.example/override")}`), taskContext(DETAIL_TASK_ID));
    assert.equal(response.status, 307);
    assert.equal(response.headers.get("Location"), `https://objects.example.test/public/${DETAIL_PUBLIC_KEY}`);
    assert.equal(response.headers.get("X-Content-Type-Options"), "nosniff");
    assert.equal(response.headers.get("Content-Type"), "application/octet-stream");
    assert.equal(response.headers.get("Cache-Control"), "no-store");
    assert.equal(await response.text(), "");
  });

  await runCase("artifact validation and availability", scenario([], [], undefined, [], detailScenario({ availability: "unavailable" })), async () => {
    const unavailable = await getArtifact(new Request("https://site.test/api/steward/tasks/task-detail/artifact?path=runs%2Frun-detail%2Ftrajectory.json"), taskContext(DETAIL_TASK_ID));
    assert.equal(unavailable.status, 404);
    const missing = await getArtifact(new Request("https://site.test/api/steward/tasks/task-detail/artifact?path=runs%2Frun-detail%2Fmissing.txt"), taskContext(DETAIL_TASK_ID));
    assert.equal(missing.status, 404);
    const unsafe = await getArtifact(new Request("https://site.test/api/steward/tasks/task-detail/artifact?path=..%2Fprivate.txt"), taskContext(DETAIL_TASK_ID));
    assert.equal(unsafe.status, 400);
  });

  const unsafeArtifactDetail = detailScenario();
  unsafeArtifactDetail.artifacts[0]!.public_key = "private://object";
  await runCase("unsafe artifact key", scenario([], [], undefined, [], unsafeArtifactDetail), async () => {
    const response = await getArtifact(new Request("https://site.test/api/steward/tasks/task-detail/artifact?path=runs%2Frun-detail%2Ftrajectory.json"), taskContext(DETAIL_TASK_ID));
    assert.equal(response.status, 503);
    const payload = problemResponse(parseCloudResponse(await response.text()));
    assert.equal(payload.problem.code, "INTEGRITY_FAILURE");
    assert(!JSON.stringify(payload).includes("private://object"));
  });

  await runCase("immutable trajectory descriptor", scenario([], [], undefined, [], detailScenario()), async () => {
    const response = await getTranscript(new Request("https://site.test/api/steward/tasks/task-detail/transcript?run=run-detail&path=ignored.json&cursor=ignored&limit=1"), taskContext(DETAIL_TASK_ID));
    assert.equal(response.status, 200);
    const payload = dataResponse(parseCloudResponse(await response.text()));
    assert.equal(payload.schemaVersion, "3.0");
    if (!("runId" in payload.data) || !("publicKey" in payload.data)) throw new Error("expected trajectory descriptor");
    assert.equal(payload.data.taskId, DETAIL_TASK_ID);
    assert.equal(payload.data.pipelineId, DETAIL_PIPELINE_ID);
    assert.equal(payload.data.runId, DETAIL_RUN_ID);
    assert.equal(payload.data.artifactId, "artifact-atif");
    for (const partialField of ["records", "cursor", "prefix", "partial"]) assert(!(partialField in payload.data));
  });

  await runCase("unknown task path and run", scenario([], [], undefined, [], detailScenario()), async () => {
    const unknownTask = await getTaskDetail(new Request("https://site.test/api/steward/tasks/missing"), taskContext("missing"));
    assert.equal(unknownTask.status, 404);
    const unknownRun = await getTranscript(new Request("https://site.test/api/steward/tasks/task-detail/transcript?run=missing-run"), taskContext(DETAIL_TASK_ID));
    assert.equal(unknownRun.status, 404);
    const invalidRun = await getTranscript(new Request("https://site.test/api/steward/tasks/task-detail/transcript?run=../private"), taskContext(DETAIL_TASK_ID));
    assert.equal(invalidRun.status, 400);
    const invalidTask = await getTaskDetail(new Request("https://site.test/api/steward/tasks/../private"), taskContext("../private"));
    assert.equal(invalidTask.status, 400);
  });

  await runCase("detail D1 outage", { ...scenario([], []), mode: "outage" }, async () => {
    const response = await getTaskDetail(new Request("https://site.test/api/steward/tasks/task-detail"), taskContext(DETAIL_TASK_ID));
    assert.equal(response.status, 503);
    const payload = problemResponse(parseCloudResponse(await response.text()));
    assert.equal(payload.problem.code, "UNAVAILABLE");
    assert.equal(payload.problem.retryable, true);
    assert(!JSON.stringify(payload).includes("route-harness-secret"));
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

  await runCase("status unauthorized", scenario([], [], "unauthorized"), async () => {
    const response = await getStatus();
    assert.equal(response.status, 503);
    const payload = problemResponse(parseCloudResponse(await response.text()));
    assert.equal(payload.problem.code, "UNAVAILABLE");
    assert.equal(payload.problem.retryable, false);
  });

  await runCase("tasks unauthorized", scenario([], [], "unauthorized"), async () => {
    const response = await getTasks(new Request("https://site.test/api/steward/tasks?scope=history"));
    assert.equal(response.status, 503);
    const payload = problemResponse(parseCloudResponse(await response.text()));
    assert.equal(payload.problem.code, "UNAVAILABLE");
    assert.equal(payload.problem.retryable, false);
  });

  await runCase("status malformed JSON", scenario([], [], "malformed"), async () => {
    const response = await getStatus();
    assert.equal(response.status, 503);
    const payload = problemResponse(parseCloudResponse(await response.text()));
    assert.equal(payload.problem.code, "UNAVAILABLE");
    assert.equal(payload.problem.retryable, false);
  });

  await runCase("tasks malformed JSON", scenario([], [], "malformed"), async () => {
    const response = await getTasks(new Request("https://site.test/api/steward/tasks?scope=active"));
    assert.equal(response.status, 503);
    const payload = problemResponse(parseCloudResponse(await response.text()));
    assert.equal(payload.problem.code, "UNAVAILABLE");
    assert.equal(payload.problem.retryable, false);
  });

  await runCase("rate limited", { ...scenario([], []), mode: "rate-limited" }, async () => {
    const response = await getStatus();
    assert.equal(response.status, 429);
    const payload = problemResponse(parseCloudResponse(await response.text()));
    assert.equal(payload.problem.code, "RATE_LIMITED");
    assert.equal(payload.problem.retryable, true);
    assert(!JSON.stringify(payload).includes("route-harness-secret"));
  });

  await runCase("outage", { ...scenario([], []), mode: "outage" }, async () => {
    const response = await getStatus();
    assert.equal(response.status, 503);
    const payload = problemResponse(parseCloudResponse(await response.text()));
    assert.equal(payload.problem.code, "UNAVAILABLE");
    assert.equal(payload.problem.retryable, true);
    assert(!JSON.stringify(payload).includes("route-harness-secret"));
  });

  await runCase("server error", { ...scenario([], []), mode: "server-error" }, async () => {
    const response = await getTasks(new Request("https://site.test/api/steward/tasks?scope=history"));
    assert.equal(response.status, 503);
    const payload = problemResponse(parseCloudResponse(await response.text()));
    assert.equal(payload.problem.code, "UNAVAILABLE");
    assert.equal(payload.problem.retryable, true);
  });

  await runCase("malformed D1", { ...scenario([], []), mode: "malformed" }, async () => {
    const response = await getStatus();
    assert.equal(response.status, 503);
    const payload = problemResponse(parseCloudResponse(await response.text()));
    assert.equal(payload.problem.code, "UNAVAILABLE");
    assert.equal(payload.problem.retryable, false);
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

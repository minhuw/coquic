import assert from "node:assert/strict";
import Module, { createRequire } from "node:module";
import { test } from "node:test";
import { dirname, resolve } from "node:path";

type CloudRepositoryModule = typeof import("../../lib/steward-archive/cloud-repository");
const requireForTest = createRequire(resolve(process.cwd(), "tests/steward-archive/cloud-repository.test.ts"));
const runtimeModule = Module as unknown as { _resolveFilename: (request: string, parent?: unknown, isMain?: boolean, options?: unknown) => string };

function loadRepository(): CloudRepositoryModule {
  const empty = resolve(dirname(requireForTest.resolve("next/package.json")), "dist/compiled/server-only/empty.js");
  const previous = runtimeModule._resolveFilename;
  runtimeModule._resolveFilename = function (request, parent, isMain, options) {
    if (request === "server-only") return empty;
    return previous.call(this, request, parent, isMain, options);
  };
  try { return requireForTest(resolve(process.cwd(), "lib/steward-archive/cloud-repository.ts")) as CloudRepositoryModule; }
  finally { runtimeModule._resolveFilename = previous; }
}

const repositoryModule = loadRepository();
const { CloudRepository, CloudRepositoryDataError, STATUS_STATEMENT } = repositoryModule;
const { decodePublicationCursor } = requireForTest(resolve(process.cwd(), "lib/steward-archive/publication.ts")) as typeof import("../../lib/steward-archive/publication");

const latestPublication = "publication-latest";

type RawRow = Record<string, unknown>;

function response(rows: readonly RawRow[]) {
  return { result: [{ results: rows, meta: {} }] };
}

function statusRow(count = 1, publicationId: string | null = latestPublication): RawRow {
  return {
    task_count: count,
    latest_publication_at: count === 0 ? null : "2026-07-28T00:00:02Z",
    latest_publication_id: publicationId,
  };
}

function taskRow(
  taskId: string,
  updatedAt: string,
  lifecycleState: "active" | "completed" | "failed" | "cancelled" = "active",
): RawRow {
  const completedAt = lifecycleState === "active" ? null : "2026-07-28T00:00:01Z";
  return {
    head_updated_at: updatedAt,
    publication_id: `publication-${taskId}`,
    task_id: taskId,
    title: `${taskId} title`,
    lifecycle_state: lifecycleState,
    created_at: "2026-07-28T00:00:00Z",
    completed_at: completedAt,
    expected_event_count: 2,
    expected_artifact_count: 1,
    event_count: 2,
    artifact_count: 1,
    pipeline_id: `pipeline-${taskId}`,
    run_id: `run-${taskId}`,
    run_state: "completed",
    redaction_applied_min: 0,
    redaction_applied_max: 0,
    original_retained_min: 1,
    original_retained_max: 1,
  };
}

class FakeClient {
  readonly calls: { statement: string; params: readonly unknown[] }[] = [];
  private readonly pending: (unknown | Error)[];

  constructor(...responses: (unknown | Error)[]) {
    this.pending = responses;
  }

  async query(statement: string, params: readonly unknown[] = []) {
    this.calls.push({ statement, params });
    const result = this.pending.shift();
    if (result instanceof Error) throw result;
    if (result === undefined) throw new Error("missing fake D1 response");
    return result as ReturnType<typeof response>;
  }
}

test("reports empty and ready status from the visible publication join", async () => {
  const empty = new CloudRepository({ client: new FakeClient(response([statusRow(0, null)])) });
  assert.deepEqual(await empty.getStatus(), { state: "empty", taskCount: 0, latestPublicationAt: null });

  const readyClient = new FakeClient(response([statusRow()]));
  const ready = new CloudRepository({ client: readyClient });
  assert.deepEqual(await ready.getStatus(), { state: "available", taskCount: 1, latestPublicationAt: "2026-07-28T00:00:02Z" });
  assert.match(readyClient.calls[0]!.statement, /task_heads[\s\S]+publication_generations[\s\S]+state = 'visible'[\s\S]+tasks/);
  assert.equal(readyClient.calls[0]!.statement, STATUS_STATEMENT);
});

test("lists active tasks with equal timestamps, bounded limits, and separate completeness", async () => {
  const first = taskRow("task-b", "2026-07-28T00:00:03Z");
  const second = taskRow("task-a", "2026-07-28T00:00:03Z");
  const client = new FakeClient(response([statusRow(2)]), response([first, second]), response([{ task_count: 2 }]));
  const page = await new CloudRepository({ client }).listTasks({ scope: "active", limit: 0 });
  assert.equal(page.tasks.length, 1);
  assert.equal(page.tasks[0]!.taskId, "task-b");
  assert.equal(page.tasks[0]!.completeness, "complete");
  assert.equal(page.tasks[0]!.lifecycleState, "active");
  assert.equal(page.tasks[0]!.completedAt, null);
  assert.equal(page.tasks[0]!.completedRunId, "run-task-b");
  assert(page.nextCursor);
  assert.deepEqual(client.calls[1]!.params, [2]);
  assert.equal(client.calls[2]!.params.length, 0);
  for (const call of client.calls) assert.match(call.statement, /task_heads[\s\S]+publication_generations[\s\S]+state = 'visible'/);
});

test("supports forward and backward cursors without losing a tied timestamp", async () => {
  const firstRow = taskRow("task-b", "2026-07-28T00:00:03Z");
  const secondRow = taskRow("task-a", "2026-07-28T00:00:03Z");
  const newerRow = taskRow("task-c", "2026-07-28T00:00:03Z");
  const firstClient = new FakeClient(response([statusRow(3)]), response([firstRow, secondRow]), response([{ task_count: 3 }]));
  const first = await new CloudRepository({ client: firstClient }).listTasks("active", { limit: 1 });
  assert(first.nextCursor);
  const decoded = decodePublicationCursor(first.nextCursor, { query: "tasks-active", publicationId: latestPublication });
  assert.deepEqual(decoded.sort, ["2026-07-28T00:00:03Z", "task-b", "next"]);

  const nextClient = new FakeClient(
    response([statusRow(3)]),
    response([{ head_updated_at: "2026-07-28T00:00:03Z", task_id: "task-b" }]),
    response([secondRow]),
    response([{ task_count: 3 }]),
  );
  const next = await new CloudRepository({ client: nextClient }).listTasks("active", first.nextCursor, 1);
  assert.deepEqual(next.tasks.map((task) => task.taskId), ["task-a"]);
  assert(next.previousCursor);
  assert.equal(next.nextCursor, null);

  const previousClient = new FakeClient(
    response([statusRow(3)]),
    response([{ head_updated_at: "2026-07-28T00:00:03Z", task_id: "task-a" }]),
    response([firstRow, newerRow]),
    response([{ task_count: 3 }]),
  );
  const previous = await new CloudRepository({ client: previousClient }).listTasks("active", next.previousCursor, 1);
  assert.deepEqual(previous.tasks.map((task) => task.taskId), ["task-b"]);
  assert(previous.previousCursor);
  assert(previous.nextCursor);
});

test("keeps active-after-planning separate from terminal history", async () => {
  const active = taskRow("task-planning", "2026-07-28T00:00:04Z", "active");
  const activeClient = new FakeClient(response([statusRow()]), response([active]), response([{ task_count: 1 }]));
  const activePage = await new CloudRepository({ client: activeClient }).listActiveTasks({ limit: 10 });
  assert.equal(activePage.tasks[0]!.lifecycleState, "active");
  assert.equal(activePage.tasks[0]!.completedRunId, "run-task-planning");

  const history = taskRow("task-terminal", "2026-07-28T00:00:05Z", "completed");
  const historyClient = new FakeClient(response([statusRow()]), response([history]), response([{ task_count: 1 }]));
  const historyPage = await new CloudRepository({ client: historyClient }).listHistoryTasks({ limit: 10 });
  assert.equal(historyPage.tasks[0]!.lifecycleState, "completed");
  assert.equal(historyPage.tasks[0]!.completedAt, "2026-07-28T00:00:01Z");
});

test("rejects stale, malformed, private-shaped, and inconsistent remote rows", async () => {
  const cursor = repositoryModule.encodePublicationCursor({ query: "tasks-active", publicationId: "publication-old", sort: ["2026-07-28T00:00:03Z", "task-old", "next"] });
  const staleClient = new FakeClient(response([statusRow(1, latestPublication)]));
  await assert.rejects(() => new CloudRepository({ client: staleClient }).listTasks("active", cursor), (error: unknown) => error instanceof repositoryModule.PublicationCursorError && error.code === "STALE_CURSOR");

  const privateRow = { ...taskRow("task-private", "2026-07-28T00:00:03Z"), credential_path: "/private/secret" };
  const privateClient = new FakeClient(response([statusRow()]), response([privateRow]));
  await assert.rejects(() => new CloudRepository({ client: privateClient }).listTasks("active"), CloudRepositoryDataError);

  const inconsistent = taskRow("task-bad", "2026-07-28T00:00:03Z");
  inconsistent.event_count = 1;
  const inconsistentClient = new FakeClient(response([statusRow()]), response([inconsistent]));
  await assert.rejects(() => new CloudRepository({ client: inconsistentClient }).listTasks("active"), CloudRepositoryDataError);
});

test("surfaces a remote outage without inventing local readiness", async () => {
  const outage = new Error("D1 unavailable");
  await assert.rejects(() => new CloudRepository({ client: new FakeClient(outage) }).getStatus(), outage);
});

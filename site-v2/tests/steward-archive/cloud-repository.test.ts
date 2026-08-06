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
const {
  CloudRepository,
  CloudRepositoryDataError,
  ARTIFACT_DESCRIPTOR_STATEMENT,
  STATUS_STATEMENT,
  STATUS_VALIDATION_NEXT_STATEMENT,
  STATUS_VALIDATION_STATEMENT,
  TASK_DETAIL_ARTIFACTS_STATEMENT,
  TASK_DETAIL_EVENTS_STATEMENT,
  TASK_DETAIL_PIPELINES_STATEMENT,
  TASK_DETAIL_RUNS_STATEMENT,
  TASK_DETAIL_STATEMENT,
  USAGE_CONTEXT_STATEMENT,
  USAGE_GLOBAL_STATEMENT,
  USAGE_INVOCATION_CONTEXT_STATEMENT,
  USAGE_INVOCATION_BOUNDARY_STATEMENT,
  USAGE_INVOCATION_COUNT_STATEMENT,
  USAGE_INVOCATION_TOTAL_STATEMENT,
  USAGE_INVOCATION_RUN_STATEMENT,
  USAGE_INVOCATION_RUN_COUNT_STATEMENT,
  USAGE_INVOCATION_RUN_TOTAL_STATEMENT,
  USAGE_INVOCATION_RUN_NEXT_STATEMENT,
  USAGE_INVOCATION_RUN_PREVIOUS_STATEMENT,
  USAGE_INVOCATION_NEXT_STATEMENT,
  USAGE_INVOCATION_PREVIOUS_STATEMENT,
  USAGE_INVOCATION_STATEMENT,
  USAGE_SUMMARY_STATEMENT,
  USAGE_TURN_BOUNDARY_STATEMENT,
  USAGE_TURN_COUNT_STATEMENT,
  USAGE_TURN_FIRST_STATEMENT,
  USAGE_TURN_NEXT_STATEMENT,
  USAGE_TURN_PREVIOUS_STATEMENT,
} = repositoryModule;
const { decodePublicationCursor, encodeUsageCursor, encodeUsageInvocationCursor } = requireForTest(resolve(process.cwd(), "lib/steward-archive/publication.ts")) as typeof import("../../lib/steward-archive/publication");

const latestPublication = "publication-latest";

type RawRow = Record<string, unknown>;

function response(rows: readonly RawRow[]) {
  return { result: [{ results: rows, meta: {} }] };
}

function publicContract(taskId: string, publicationId: string, runId: string, updatedAt = "2026-07-28T00:00:03Z"): RawRow {
  return {
    head_updated_at: updatedAt,
    head_state: "visible",
    publication_id: publicationId,
    generation_task_id: taskId,
    generation_run_id: runId,
    generation_metadata_digest: "a".repeat(64),
    generation_idempotency_key: `retry-${taskId}`,
    generation_state: "visible",
    generation_expected_task_count: 1,
    generation_expected_pipeline_count: 1,
    generation_expected_run_count: 1,
    generation_expected_event_count: 2,
    generation_expected_artifact_count: 1,
    generation_created_at: "2026-07-28T00:00:00Z",
    generation_exposed_at: "2026-07-28T00:00:02Z",
    task_id: taskId,
  };
}

function statusSummary(count: number, latestPublicationId = latestPublication, latestPublicationAt = "2026-07-28T00:00:02Z"): RawRow {
  return {
    task_count: count,
    latest_publication_at: count === 0 ? null : latestPublicationAt,
    latest_publication_id: count === 0 ? null : latestPublicationId,
  };
}

function statusRow(taskId = "status-task", publicationId: string = latestPublication): RawRow {
  return publicContract(taskId, publicationId, `run-${taskId}`);
}

function statusRows(count: number, publicationId = latestPublication): RawRow[] {
  return Array.from({ length: count }, (_, index) => statusRow(`status-task-${index}`, publicationId)).reverse();
}

function taskRow(
  taskId: string,
  updatedAt: string,
  lifecycleState: "active" | "completed" | "failed" | "cancelled" = "active",
): RawRow {
  const completedAt = lifecycleState === "active" ? null : "2026-07-28T00:00:01Z";
  return {
    ...publicContract(taskId, `publication-${taskId}`, `run-${taskId}`, updatedAt),
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

const detailTaskId = "task-detail";
const detailPublicationId = "publication-detail";
const detailRunId = "run-detail";
const detailPipelineId = "pipeline-detail";
const detailDigest = "b".repeat(64);
const detailPublicKey = `v1/tasks/${detailTaskId}/objects/sha256/bb/${detailDigest}`;

function detailTaskRow(lifecycleState: "active" | "completed" = "completed"): RawRow {
  return {
    ...publicContract(detailTaskId, detailPublicationId, detailRunId),
    generation_expected_pipeline_count: 1,
    generation_expected_run_count: 1,
    generation_expected_event_count: 2,
    generation_expected_artifact_count: 1,
    title: "Detail task",
    lifecycle_state: lifecycleState,
    created_at: "2026-07-28T00:00:00Z",
    completed_at: lifecycleState === "active" ? null : "2026-07-28T00:00:03Z",
  };
}

function detailPipelineRow(): RawRow {
  return { publication_id: detailPublicationId, pipeline_id: detailPipelineId, task_id: detailTaskId, name: "Detail pipeline", created_at: "2026-07-28T00:00:00Z" };
}

function detailRunRow(runState: "completed" | "failed" | "cancelled" = "completed"): RawRow {
  return {
    publication_id: detailPublicationId,
    run_id: detailRunId,
    task_id: detailTaskId,
    pipeline_id: detailPipelineId,
    role: "planning",
    run_state: runState,
    started_at: "2026-07-28T00:00:00Z",
    completed_at: "2026-07-28T00:00:01Z",
    duration_ms: 1_000,
    atif_digest: detailDigest,
  };
}

function detailEventRows(): RawRow[] {
  return [
    { publication_id: detailPublicationId, task_id: detailTaskId, sequence: 1, event_type: "started", occurred_at: "2026-07-28T00:00:00Z", summary: "Started" },
    { publication_id: detailPublicationId, task_id: detailTaskId, sequence: 2, event_type: "completed", occurred_at: "2026-07-28T00:00:01Z", summary: "Completed" },
  ];
}

function detailArtifactRow(availability: "available" | "unavailable" = "available"): RawRow {
  return {
    publication_id: detailPublicationId,
    artifact_id: "artifact-atif",
    task_id: detailTaskId,
    run_id: detailRunId,
    logical_path: "runs/run-detail/trajectory.json",
    public_key: detailPublicKey,
    media_type: "application/json",
    byte_size: 128,
    sha256: detailDigest,
    availability,
    redaction_applied: 0,
    original_retained: 1,
  };
}

function detailResponses(options: { lifecycleState?: "active" | "completed"; availability?: "available" | "unavailable" } = {}) {
  return [
    response([detailTaskRow(options.lifecycleState)]),
    response([detailPipelineRow()]),
    response([detailRunRow()]),
    response(detailEventRows()),
    response([detailArtifactRow(options.availability)]),
  ];
}

const usageGenerationId = "usage-generation";
const usageTaskId = "task-usage";
const usagePublicationId = "publication-usage";
const usagePipelineId = "pipeline-usage";
const usageRunId = "run-usage";
const usageInvocationId = "invocation-usage";
const usageDigest = "c".repeat(64);

function usageContextRow(overrides: RawRow = {}): RawRow {
  return {
    task_id: usageTaskId, publication_id: usagePublicationId, task_head_state: "visible", task_head_updated_at: "2026-07-28T00:00:03Z",
    task_head_usage_generation_id: usageGenerationId, generation_publication_id: usagePublicationId, generation_state: "visible",
    generation_exposed_at: "2026-07-28T00:00:02Z", usage_head_generation_id: usageGenerationId, usage_head_state: "visible",
    usage_head_updated_at: "2026-07-28T00:00:03Z", usage_generation_id: usageGenerationId, usage_publication_id: usagePublicationId,
    usage_task_id: usageTaskId, usage_schema_version: "1.0", usage_metadata_digest: "e".repeat(64), usage_generation_state: "visible",
    usage_generation_exposed_at: "2026-07-28T00:00:02Z", ...overrides,
  };
}

function missingUsageContextRow(): RawRow {
  return usageContextRow({
    usage_head_generation_id: null, usage_head_state: null, usage_head_updated_at: null, usage_generation_id: null,
    usage_publication_id: null, usage_task_id: null, usage_schema_version: null, usage_metadata_digest: null,
    usage_generation_state: null, usage_generation_exposed_at: null,
  });
}

function usageSummaryRow(overrides: RawRow = {}): RawRow {
  return {
    summary_id: "summary-task", usage_generation_id: usageGenerationId, publication_id: usagePublicationId, task_id: usageTaskId,
    run_id: null, scope: "task", coverage: "complete", covered_invocations: 1, expected_invocations: 1,
    known_token_subtotal: 18, known_cost_subtotal_micro_usd: 60, prompt_tokens: 11, cached_tokens: 2, uncached_tokens: 9,
    completion_tokens: 7, reasoning_tokens: 3, total_tokens: 18, uncached_input_cost_micro_usd: 10,
    cached_input_cost_micro_usd: 20, output_cost_micro_usd: 30, total_cost_micro_usd: 60, price_provenance_digest: usageDigest,
    ...overrides,
  };
}

function usageInvocationRow(overrides: RawRow = {}): RawRow {
  return {
    invocation_id: usageInvocationId, usage_generation_id: usageGenerationId, publication_id: usagePublicationId, task_id: usageTaskId,
    pipeline_id: usagePipelineId, run_id: usageRunId, ownership_class: "task-owned", retry_ordinal: 0,
    started_at: "2026-07-28T00:00:00Z", completed_at: "2026-07-28T00:00:01Z", model: "gpt-fixture", billing_mode: "api",
    process_outcome: "success", coverage: "complete", issue_count: 0, covered_turns: 2, expected_turns: 2,
    prompt_tokens: 11, cached_tokens: 2, uncached_tokens: 9, completion_tokens: 7, reasoning_tokens: 3, total_tokens: 18,
    uncached_input_cost_micro_usd: 10, cached_input_cost_micro_usd: 20, output_cost_micro_usd: 30, total_cost_micro_usd: 60,
    price_entry_digest: usageDigest, ...overrides,
  };
}

function usageInvocationAt(runId: string, retryOrdinal: number, invocationId: string): RawRow {
  return usageInvocationRow({ run_id: runId, retry_ordinal: retryOrdinal, invocation_id: invocationId });
}

function usageGlobalRow(overrides: RawRow = {}): RawRow {
  return {
    global_id: "global-usage", usage_generation_id: usageGenerationId, period_kind: "lifetime", period_key: "lifetime",
    model: "gpt-fixture", ownership_class: "task-owned", coverage: "complete", covered_invocations: 1, expected_invocations: 1,
    known_token_subtotal: 18, known_cost_subtotal_micro_usd: 60, prompt_tokens: 11, cached_tokens: 2, uncached_tokens: 9,
    completion_tokens: 7, reasoning_tokens: 3, total_tokens: 18, uncached_input_cost_micro_usd: 10,
    cached_input_cost_micro_usd: 20, output_cost_micro_usd: 30, total_cost_micro_usd: 60, price_provenance_digest: usageDigest,
    aggregate_only: 1, ...overrides,
  };
}

function overheadGlobalRow(overrides: RawRow = {}): RawRow {
  return usageGlobalRow({
    global_id: "global-overhead",
    usage_generation_id: "usage-overhead",
    period_kind: "daily",
    period_key: "2026-07-28",
    model: "gpt-overhead",
    ownership_class: "steward-overhead",
    coverage: "unavailable",
    covered_invocations: 0,
    expected_invocations: 0,
    known_token_subtotal: null,
    known_cost_subtotal_micro_usd: null,
    prompt_tokens: null,
    cached_tokens: null,
    uncached_tokens: null,
    completion_tokens: null,
    reasoning_tokens: null,
    total_tokens: null,
    uncached_input_cost_micro_usd: null,
    cached_input_cost_micro_usd: null,
    output_cost_micro_usd: null,
    total_cost_micro_usd: null,
    price_provenance_digest: null,
    ...overrides,
  });
}

function usageTurnRow(ordinal: number, turnId = `turn-${ordinal}`, overrides: RawRow = {}): RawRow {
  return {
    turn_id: turnId, usage_generation_id: usageGenerationId, invocation_id: usageInvocationId, publication_id: usagePublicationId,
    task_id: usageTaskId, run_id: usageRunId, ordinal, prompt_tokens: 5, cached_tokens: 1, uncached_tokens: 4,
    completion_tokens: 2, reasoning_tokens: 1, total_tokens: 7, uncached_input_cost_micro_usd: 4,
    cached_input_cost_micro_usd: 5, output_cost_micro_usd: 6, total_cost_micro_usd: 15, price_entry_digest: usageDigest,
    ...overrides,
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

test("reads only visible cached usage and preserves D1 numeric values", async () => {
  const runSummary = usageSummaryRow({ summary_id: "summary-run", run_id: usageRunId, scope: "run" });
  const client = new FakeClient(
    response([usageContextRow()]),
    response([usageSummaryRow(), runSummary]),
    response([usageInvocationRow()]),
    response([usageGlobalRow(), usageGlobalRow({ global_id: "global-daily", period_kind: "daily", period_key: "2026-07-28" })]),
  );
  const usage = await new CloudRepository({ client }).getTaskUsage(usageTaskId);
  assert(usage && !Array.isArray(usage) && !('kind' in usage));
  assert.equal(usage.summaries[0]!.totalTokens, 18);
  assert.equal(usage.summaries[0]!.totalCostMicroUsd, 60);
  assert.equal(usage.invocations[0]!.cachedTokens, 2);
  assert.equal(usage.globals[0]!.daily[0]!.totalCostMicroUsd, 60);
  assert.deepEqual(client.calls.map((call) => call.statement), [USAGE_CONTEXT_STATEMENT, USAGE_SUMMARY_STATEMENT, USAGE_INVOCATION_STATEMENT, USAGE_GLOBAL_STATEMENT]);
  assert.equal(client.calls[1]!.params.at(-1), 4_097);
  assert.equal(client.calls[2]!.params.at(-1), 129);
  assert.equal(client.calls[3]!.params.at(-1), 4_097);
  for (const call of client.calls) assert.match(call.statement, /SELECT/);
  assert(client.calls.every((call) => /^\s*SELECT/i.test(call.statement)));
});

test("reads detached overhead globals without task joins", async () => {
  const client = new FakeClient(response([overheadGlobalRow()]));
  const usage = await new CloudRepository({ client }).getGlobalUsage();
  assert(Array.isArray(usage));
  assert.equal(usage[0]!.daily[0]!.ownershipClass, "steward-overhead");
  assert.equal(usage[0]!.daily[0]!.totalTokens, null);
  assert.match(client.calls[0]!.statement, /UNION ALL/);
  assert.match(client.calls[0]!.statement, /ug\.publication_id IS NULL/);
  assert.match(client.calls[0]!.statement, /ug\.task_id IS NULL/);
  assert.match(client.calls[0]!.statement, /gh\.ownership_class = 'task-owned'/);
  assert.match(client.calls[0]!.statement, /gh\.ownership_class = 'steward-overhead'/);
});

test("rejects malformed or mismatched overhead global rows", async () => {
  const staged = await new CloudRepository({ client: new FakeClient(response([overheadGlobalRow({ generation_state: "staged" })])) }).getGlobalUsage();
  assert.deepEqual(staged, { kind: "unavailable", reason: "invalid" });

  const mismatched = await new CloudRepository({ client: new FakeClient(response([overheadGlobalRow({ ownership_class: "invalid-owner" })])) }).getGlobalUsage();
  assert.deepEqual(mismatched, { kind: "unavailable", reason: "invalid" });

  const privateShape = await new CloudRepository({ client: new FakeClient(response([overheadGlobalRow({ private_path: "hidden" })])) }).getGlobalUsage();
  assert.deepEqual(privateShape, { kind: "unavailable", reason: "invalid" });
});

test("distinguishes an absent task, missing usage head, corrupt usage, and D1 outage", async () => {
  const absent = await new CloudRepository({ client: new FakeClient(response([])) }).getTaskUsage(usageTaskId);
  assert.equal(absent, null);

  const missing = await new CloudRepository({ client: new FakeClient(response([missingUsageContextRow()])) }).getTaskUsage(usageTaskId);
  assert.deepEqual(missing, { kind: "unavailable", reason: "missing" });

  const corrupt = await new CloudRepository({ client: new FakeClient(response([usageContextRow({ usage_metadata_digest: "bad" })])) }).getTaskUsage(usageTaskId);
  assert.deepEqual(corrupt, { kind: "unavailable", reason: "invalid" });

  const outage = await new CloudRepository({ client: new FakeClient(new Error("D1 timeout")) }).getTaskUsage(usageTaskId);
  assert.deepEqual(outage, { kind: "unavailable", reason: "unavailable" });

  const summaryOutage = await new CloudRepository({ client: new FakeClient(response([usageContextRow()]), new Error("rate limit")) }).getTaskUsageSummary(usageTaskId);
  assert.deepEqual(summaryOutage, { kind: "unavailable", reason: "unavailable" });
  const invocationOutage = await new CloudRepository({ client: new FakeClient(response([usageContextRow()]), new Error("rate limit")) }).getUsageInvocations(usageTaskId);
  assert.deepEqual(invocationOutage, { kind: "unavailable", reason: "unavailable" });
  const globalOutage = await new CloudRepository({ client: new FakeClient(new Error("rate limit")) }).getGlobalUsage();
  assert.deepEqual(globalOutage, { kind: "unavailable", reason: "unavailable" });
});

test("rejects malformed and cross-owner usage rows while retaining fixed visibility joins", async () => {
  const malformed = usageSummaryRow({ private_path: "hidden" });
  const client = new FakeClient(response([usageContextRow()]), response([malformed]));
  const result = await new CloudRepository({ client }).getTaskUsageSummary(usageTaskId);
  assert.deepEqual(result, { kind: "unavailable", reason: "invalid" });
  assert.match(client.calls[0]!.statement, /task_heads/);
  assert.match(client.calls[0]!.statement, /publication_generations/);
  assert.match(client.calls[0]!.statement, /usage_heads/);
  assert.match(client.calls[1]!.statement, /state = 'visible'/);
  assert.match(client.calls[1]!.statement, /exposed_at IS NOT NULL/);
  assert.match(client.calls[1]!.statement, /pipelines/);
  assert.match(client.calls[1]!.statement, /runs/);

  const wrongOwner = usageInvocationRow({ task_id: "task-other" });
  const invocationResult = await new CloudRepository({ client: new FakeClient(response([usageContextRow()]), response([wrongOwner])) }).getUsageInvocations(usageTaskId);
  assert.deepEqual(invocationResult, { kind: "unavailable", reason: "invalid" });
});

test("fails closed for mismatched run and pipeline ownership", async () => {
  const mismatchedOwner = usageInvocationRow({ pipeline_id: null, run_id: null });
  const client = new FakeClient(response([usageContextRow()]), response([mismatchedOwner]));
  const result = await new CloudRepository({ client }).getUsageInvocations(usageTaskId);
  assert.deepEqual(result, { kind: "unavailable", reason: "invalid" });
  assert.match(client.calls[1]!.statement, /r\.pipeline_id = i\.pipeline_id/);
  assert.match(client.calls[1]!.statement, /pl\.pipeline_id = r\.pipeline_id/);
});

test("uses a bounded cached summary for invocation totals", async () => {
  const client = new FakeClient(
    response([usageContextRow()]),
    response([usageInvocationRow()]),
    response([{ invocation_count: 129 }]),
  );
  const page = await new CloudRepository({ client }).getUsageInvocationPage(usageTaskId, { limit: 1 });
  assert(page && !Array.isArray(page) && !("kind" in page));
  assert.equal(page.total, 129);
  assert.equal(client.calls[2]!.statement, USAGE_INVOCATION_TOTAL_STATEMENT);
  assert.equal(client.calls[2]!.statement, USAGE_INVOCATION_COUNT_STATEMENT);
  assert.match(client.calls[2]!.statement, /expected_invocations/);
  assert.match(client.calls[2]!.statement, /LIMIT 1/);
  assert.doesNotMatch(client.calls[2]!.statement, /COUNT\s*\(/i);
});

test("pages turns with generation-bound forward and backward cursors", async () => {
  const firstClient = new FakeClient(
    response([usageContextRow()]), response([usageInvocationRow()]), response([{ turn_count: 3 }]),
    response([usageTurnRow(1), usageTurnRow(2), usageTurnRow(3)]),
  );
  const repository = new CloudRepository({ client: firstClient });
  const first = await repository.getUsageTurnPage(usageTaskId, usageInvocationId, { limit: 2 });
  assert(first && !Array.isArray(first) && !('kind' in first));
  assert.deepEqual(first.turns.map((turn) => turn.ordinal), [1, 2]);
  assert(first.nextCursor);
  assert.equal(first.previousCursor, null);
  assert.deepEqual(firstClient.calls.map((call) => call.statement), [USAGE_CONTEXT_STATEMENT, USAGE_INVOCATION_CONTEXT_STATEMENT, USAGE_TURN_COUNT_STATEMENT, USAGE_TURN_FIRST_STATEMENT]);

  const nextClient = new FakeClient(
    response([usageContextRow()]), response([usageInvocationRow()]), response([{ turn_count: 3 }]), response([usageTurnRow(2)]),
    response([usageTurnRow(3)]),
  );
  const next = await new CloudRepository({ client: nextClient }).getUsageTurnPage(usageTaskId, usageInvocationId, { cursor: first.nextCursor, limit: 2 });
  assert(next && !Array.isArray(next) && !('kind' in next));
  assert.deepEqual(next.turns.map((turn) => turn.ordinal), [3]);
  assert(next.previousCursor);
  assert.equal(next.nextCursor, null);
  assert.deepEqual(nextClient.calls.map((call) => call.statement), [USAGE_CONTEXT_STATEMENT, USAGE_INVOCATION_CONTEXT_STATEMENT, USAGE_TURN_COUNT_STATEMENT, USAGE_TURN_BOUNDARY_STATEMENT, USAGE_TURN_NEXT_STATEMENT]);

  const previousClient = new FakeClient(
    response([usageContextRow()]), response([usageInvocationRow()]), response([{ turn_count: 3 }]),
    response([usageTurnRow(3)]), response([usageTurnRow(1)]),
  );
  const previous = await new CloudRepository({ client: previousClient }).getUsageTurnPage(usageTaskId, usageInvocationId, { cursor: next.previousCursor, limit: 2 });
  assert(previous && !Array.isArray(previous) && !('kind' in previous));
  assert.deepEqual(previous.turns.map((turn) => turn.ordinal), [1]);
  assert.equal(previous.nextCursor !== null, true);
  assert.deepEqual(previousClient.calls.map((call) => call.statement), [USAGE_CONTEXT_STATEMENT, USAGE_INVOCATION_CONTEXT_STATEMENT, USAGE_TURN_COUNT_STATEMENT, USAGE_TURN_BOUNDARY_STATEMENT, USAGE_TURN_PREVIOUS_STATEMENT]);
});

test("fails closed for stale, cross-owner, malformed, empty, and clamped turn pages", async () => {
  const stale = encodeUsageCursor({ query: "usage-turns", publicationId: usagePublicationId, usageGenerationId: "usage-old", taskId: usageTaskId, runId: usageRunId, invocationId: usageInvocationId, sort: [usageInvocationId, 1, "turn-1"], direction: "next" });
  await assert.rejects(
    () => new CloudRepository({ client: new FakeClient(response([usageContextRow()]), response([usageInvocationRow()]), response([{ turn_count: 1 }])) }).getUsageTurnPage(usageTaskId, usageInvocationId, { cursor: stale }),
    (error: unknown) => error instanceof repositoryModule.PublicationCursorError && error.code === "STALE_CURSOR",
  );

  const crossTask = encodeUsageCursor({ query: "usage-turns", publicationId: usagePublicationId, usageGenerationId, taskId: "task-other", runId: usageRunId, invocationId: usageInvocationId, sort: [usageInvocationId, 1, "turn-1"], direction: "next" });
  await assert.rejects(
    () => new CloudRepository({ client: new FakeClient(response([usageContextRow()]), response([usageInvocationRow()]), response([{ turn_count: 1 }])) }).getUsageTurnPage(usageTaskId, usageInvocationId, { cursor: crossTask }),
    (error: unknown) => error instanceof repositoryModule.PublicationCursorError && error.code === "STALE_CURSOR",
  );

  const malformed = "not-a-cursor";
  await assert.rejects(
    () => new CloudRepository({ client: new FakeClient(response([usageContextRow()]), response([usageInvocationRow()]), response([{ turn_count: 1 }])) }).getUsageTurnPage(usageTaskId, usageInvocationId, { cursor: malformed }),
    (error: unknown) => error instanceof repositoryModule.PublicationCursorError && error.code === "INVALID_CURSOR",
  );

  const empty = await new CloudRepository({ client: new FakeClient(response([usageContextRow()]), response([])) }).getUsageTurnPage(usageTaskId, usageInvocationId);
  assert.equal(empty, null);

  const clampedClient = new FakeClient(response([usageContextRow()]), response([usageInvocationRow()]), response([{ turn_count: 1 }]), response([usageTurnRow(1)]));
  const clamped = await new CloudRepository({ client: clampedClient }).getUsageTurnPage(usageTaskId, usageInvocationId, { limit: 999 });
  assert(clamped && !Array.isArray(clamped) && !('kind' in clamped));
  assert.equal(clampedClient.calls.at(-1)!.params.at(-1), 201);
});

test("pages task invocations beyond the legacy 128-row cap", async () => {
  const firstRows = [usageInvocationAt("run-a", 0, "invocation-a"), usageInvocationAt("run-a", 1, "invocation-b"), usageInvocationAt("run-b", 0, "invocation-c")];
  const firstClient = new FakeClient(
    response([usageContextRow()]), response(firstRows), response([{ invocation_count: 129 }]),
  );
  const first = await new CloudRepository({ client: firstClient }).getUsageInvocationPage(usageTaskId, { limit: 2 });
  assert(first && !Array.isArray(first) && !("kind" in first));
  assert.deepEqual(first.invocations.map((invocation) => invocation.invocationId), ["invocation-a", "invocation-b"]);
  assert.equal(first.total, 129);
  assert(first.nextCursor);
  assert.equal(first.previousCursor, null);
  assert.deepEqual(firstClient.calls.map((call) => call.statement), [USAGE_CONTEXT_STATEMENT, USAGE_INVOCATION_STATEMENT, USAGE_INVOCATION_COUNT_STATEMENT]);
  assert.equal(firstClient.calls[1]!.params.at(-1), 3);

  const nextClient = new FakeClient(
    response([usageContextRow()]), response([usageInvocationAt("run-a", 1, "invocation-b")]), response([usageInvocationAt("run-b", 0, "invocation-c")]), response([{ invocation_count: 129 }]),
  );
  const next = await new CloudRepository({ client: nextClient }).getUsageInvocationPage(usageTaskId, { cursor: first.nextCursor, limit: 2 });
  assert(next && !Array.isArray(next) && !("kind" in next));
  assert.deepEqual(next.invocations.map((invocation) => invocation.invocationId), ["invocation-c"]);
  assert.equal(next.nextCursor, null);
  assert(next.previousCursor);
  assert.deepEqual(nextClient.calls.map((call) => call.statement), [USAGE_CONTEXT_STATEMENT, USAGE_INVOCATION_BOUNDARY_STATEMENT, USAGE_INVOCATION_NEXT_STATEMENT, USAGE_INVOCATION_COUNT_STATEMENT]);
  assert.deepEqual(nextClient.calls[2]!.params, [usageTaskId, "run-a", "run-a", 1, 1, "invocation-b", 3]);
});

test("pages run-scoped invocations backward and rejects generation or run drift", async () => {
  const firstClient = new FakeClient(
    response([usageContextRow()]), response([usageInvocationAt(usageRunId, 0, "invocation-a"), usageInvocationAt(usageRunId, 1, "invocation-b")]), response([{ invocation_count: 3 }]),
  );
  const first = await new CloudRepository({ client: firstClient }).getUsageInvocations(usageTaskId, usageRunId, { limit: 1 });
  assert(first && !Array.isArray(first) && !("kind" in first));
  assert.deepEqual(first.invocations.map((invocation) => invocation.invocationId), ["invocation-a"]);
  assert(first.nextCursor);
  assert.deepEqual(firstClient.calls.map((call) => call.statement), [USAGE_CONTEXT_STATEMENT, USAGE_INVOCATION_RUN_STATEMENT, USAGE_INVOCATION_RUN_COUNT_STATEMENT]);
  assert.equal(firstClient.calls[2]!.statement, USAGE_INVOCATION_RUN_TOTAL_STATEMENT);
  assert.deepEqual(firstClient.calls[2]!.params, [usageTaskId, usageRunId]);

  const nextClient = new FakeClient(
    response([usageContextRow()]), response([usageInvocationAt(usageRunId, 0, "invocation-a")]), response([usageInvocationAt(usageRunId, 1, "invocation-b")]), response([{ invocation_count: 3 }]),
  );
  const next = await new CloudRepository({ client: nextClient }).getUsageInvocationPage(usageTaskId, usageRunId, { cursor: first.nextCursor, limit: 1 });
  assert(next && !Array.isArray(next) && !("kind" in next));
  assert.deepEqual(next.invocations.map((invocation) => invocation.invocationId), ["invocation-b"]);
  assert(next.previousCursor);
  assert.deepEqual(nextClient.calls.map((call) => call.statement), [USAGE_CONTEXT_STATEMENT, USAGE_INVOCATION_BOUNDARY_STATEMENT, USAGE_INVOCATION_RUN_NEXT_STATEMENT, USAGE_INVOCATION_RUN_COUNT_STATEMENT]);

  const previousClient = new FakeClient(
    response([usageContextRow()]), response([usageInvocationAt(usageRunId, 1, "invocation-b")]), response([usageInvocationAt(usageRunId, 0, "invocation-a")]), response([{ invocation_count: 3 }]),
  );
  const previous = await new CloudRepository({ client: previousClient }).getUsageInvocationPage(usageTaskId, usageRunId, { cursor: next.previousCursor, limit: 1 });
  assert(previous && !Array.isArray(previous) && !("kind" in previous));
  assert.deepEqual(previous.invocations.map((invocation) => invocation.invocationId), ["invocation-a"]);
  assert.deepEqual(previousClient.calls.map((call) => call.statement), [USAGE_CONTEXT_STATEMENT, USAGE_INVOCATION_BOUNDARY_STATEMENT, USAGE_INVOCATION_RUN_PREVIOUS_STATEMENT, USAGE_INVOCATION_RUN_COUNT_STATEMENT]);

  const stale = encodeUsageInvocationCursor({ publicationId: usagePublicationId, usageGenerationId: "usage-old", taskId: usageTaskId, runId: usageRunId, sort: [usageRunId, 0, "invocation-a"], direction: "next" });
  await assert.rejects(
    () => new CloudRepository({ client: new FakeClient(response([usageContextRow()])) }).getUsageInvocationPage(usageTaskId, usageRunId, { cursor: stale }),
    (error: unknown) => error instanceof repositoryModule.PublicationCursorError && error.code === "STALE_CURSOR",
  );
});

function statusKey(row: RawRow): [string, string, string] {
  return [String(row.generation_exposed_at), String(row.publication_id), String(row.task_id)];
}

function compareStatusKey(left: readonly string[], right: readonly string[]): number {
  for (let index = 0; index < left.length; index += 1) {
    if (left[index] !== right[index]) return left[index]! < right[index]! ? -1 : 1;
  }
  return 0;
}

class BoundedStatusClient {
  readonly calls: { statement: string; params: readonly unknown[] }[] = [];
  private readonly rows: readonly RawRow[];

  constructor(rows: readonly RawRow[]) {
    this.rows = [...rows].sort((left, right) => compareStatusKey(statusKey(right), statusKey(left)));
  }

  async query(statement: string, params: readonly unknown[] = []) {
    this.calls.push({ statement, params });
    let rows: readonly RawRow[];
    if (statement === STATUS_STATEMENT) {
      const first = this.rows[0];
      rows = [statusSummary(this.rows.length, String(first?.publication_id), String(first?.generation_exposed_at))];
    } else if (statement === STATUS_VALIDATION_STATEMENT) {
      rows = this.rows.slice(0, Number(params[0]));
    } else if (statement === STATUS_VALIDATION_NEXT_STATEMENT) {
      const cursor: [string, string, string] = [String(params[0]), String(params[2]), String(params[5])];
      const start = this.rows.findIndex((row) => compareStatusKey(statusKey(row), cursor) < 0);
      rows = start < 0 ? [] : this.rows.slice(start, start + Number(params.at(-1)));
    } else {
      throw new Error("unexpected status statement");
    }
    assert(rows.length <= 10_000);
    assert(Buffer.byteLength(JSON.stringify(response(rows)), "utf8") <= 1_048_576);
    return response(rows);
  }
}

test("reports empty and ready status from the visible publication join", async () => {
  const empty = new CloudRepository({ client: new FakeClient(response([])) });
  assert.deepEqual(await empty.getStatus(), { state: "empty", taskCount: 0, latestPublicationAt: null });

  const readyClient = new FakeClient(response([statusSummary(1)]), response([statusRow()]));
  const ready = new CloudRepository({ client: readyClient });
  assert.deepEqual(await ready.getStatus(), { state: "available", taskCount: 1, latestPublicationAt: "2026-07-28T00:00:02Z" });
  assert.match(readyClient.calls[0]!.statement, /task_heads[\s\S]+publication_generations[\s\S]+state = 'visible'[\s\S]+tasks/);
  assert.equal(readyClient.calls[0]!.statement, STATUS_STATEMENT);
  assert.equal(readyClient.calls[1]!.statement, STATUS_VALIDATION_STATEMENT);
});

test("validates 10,001 visible heads through bounded status responses", async () => {
  const rows = Array.from({ length: 10_001 }, (_, index) => statusRow(
    `status-task-${index}`,
    `publication-status-${String(index).padStart(5, "0")}`,
  ));
  const client = new BoundedStatusClient(rows);
  const status = await new CloudRepository({ client }).getStatus();
  assert.deepEqual(status, { state: "available", taskCount: 10_001, latestPublicationAt: "2026-07-28T00:00:02Z" });
  const validationCalls = client.calls.filter((call) => call.statement === STATUS_VALIDATION_STATEMENT || call.statement === STATUS_VALIDATION_NEXT_STATEMENT);
  assert.equal(validationCalls.length, Math.ceil(rows.length / 128));
  assert(validationCalls.every((call) => Number(call.params.at(-1)) <= 128));
});

test("fails closed before status or task pagination on malformed generation and head rows", async () => {
  const malformedStatus = statusRow();
  malformedStatus.generation_expected_task_count = 0;
  await assert.rejects(
    () => new CloudRepository({ client: new FakeClient(response([statusSummary(1)]), response([malformedStatus])) }).getStatus(),
    CloudRepositoryDataError,
  );

  const privatePublication = { ...taskRow("task-one", "2026-07-28T00:00:03Z"), publication_id: "private-bucket" };
  const client = new FakeClient(
    response([statusSummary(2)]),
    response(statusRows(2)),
    response([privatePublication, taskRow("task-two", "2026-07-28T00:00:02Z")]),
  );
  await assert.rejects(() => new CloudRepository({ client }).listTasks("active", null, 1), CloudRepositoryDataError);
});

test("lists active tasks with equal timestamps, bounded limits, and separate completeness", async () => {
  const first = taskRow("task-b", "2026-07-28T00:00:03Z");
  const second = taskRow("task-a", "2026-07-28T00:00:03Z");
  const client = new FakeClient(response([statusSummary(2)]), response(statusRows(2)), response([first, second]), response([{ task_count: 2 }]));
  const page = await new CloudRepository({ client }).listTasks({ scope: "active", limit: 0 });
  assert.equal(page.tasks.length, 1);
  assert.equal(page.tasks[0]!.taskId, "task-b");
  assert.equal(page.tasks[0]!.completeness, "complete");
  assert.equal(page.tasks[0]!.lifecycleState, "active");
  assert.equal(page.tasks[0]!.completedAt, null);
  assert.equal(page.tasks[0]!.completedRunId, "run-task-b");
  assert(page.nextCursor);
  assert.deepEqual(client.calls[1]!.params, [128]);
  assert.equal(client.calls[3]!.params.length, 0);
  for (const call of client.calls) assert.match(call.statement, /task_heads[\s\S]+publication_generations[\s\S]+state = 'visible'/);
});

test("supports forward and backward cursors without losing a tied timestamp", async () => {
  const firstRow = taskRow("task-b", "2026-07-28T00:00:03Z");
  const secondRow = taskRow("task-a", "2026-07-28T00:00:03Z");
  const newerRow = taskRow("task-c", "2026-07-28T00:00:03Z");
  const firstClient = new FakeClient(response([statusSummary(3)]), response(statusRows(3)), response([firstRow, secondRow]), response([{ task_count: 3 }]));
  const first = await new CloudRepository({ client: firstClient }).listTasks("active", { limit: 1 });
  assert(first.nextCursor);
  const decoded = decodePublicationCursor(first.nextCursor, { query: "tasks-active", publicationId: latestPublication });
  assert.deepEqual(decoded.sort, ["2026-07-28T00:00:03Z", "task-b", "next"]);

  const nextClient = new FakeClient(
    response([statusSummary(3)]),
    response(statusRows(3)),
    response([publicContract("task-b", "publication-task-b", "run-task-b")]),
    response([secondRow]),
    response([{ task_count: 3 }]),
  );
  const next = await new CloudRepository({ client: nextClient }).listTasks("active", first.nextCursor, 1);
  assert.deepEqual(next.tasks.map((task) => task.taskId), ["task-a"]);
  assert(next.previousCursor);
  assert.equal(next.nextCursor, null);

  const previousClient = new FakeClient(
    response([statusSummary(3)]),
    response(statusRows(3)),
    response([publicContract("task-a", "publication-task-a", "run-task-a")]),
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
  const activeClient = new FakeClient(response([statusSummary(1)]), response(statusRows(1)), response([active]), response([{ task_count: 1 }]));
  const activePage = await new CloudRepository({ client: activeClient }).listActiveTasks({ limit: 10 });
  assert.equal(activePage.tasks[0]!.lifecycleState, "active");
  assert.equal(activePage.tasks[0]!.completedRunId, "run-task-planning");

  const history = taskRow("task-terminal", "2026-07-28T00:00:05Z", "completed");
  const historyClient = new FakeClient(response([statusSummary(1)]), response(statusRows(1)), response([history]), response([{ task_count: 1 }]));
  const historyPage = await new CloudRepository({ client: historyClient }).listHistoryTasks({ limit: 10 });
  assert.equal(historyPage.tasks[0]!.lifecycleState, "completed");
  assert.equal(historyPage.tasks[0]!.completedAt, "2026-07-28T00:00:01Z");
});

test("rejects stale, malformed, private-shaped, and inconsistent remote rows", async () => {
  const cursor = repositoryModule.encodePublicationCursor({ query: "tasks-active", publicationId: "publication-old", sort: ["2026-07-28T00:00:03Z", "task-old", "next"] });
  const staleClient = new FakeClient(response([statusSummary(1)]), response(statusRows(1, latestPublication)));
  await assert.rejects(() => new CloudRepository({ client: staleClient }).listTasks("active", cursor), (error: unknown) => error instanceof repositoryModule.PublicationCursorError && error.code === "STALE_CURSOR");

  const privateRow = { ...taskRow("task-private", "2026-07-28T00:00:03Z"), credential_path: "/private/secret" };
  const privateClient = new FakeClient(response([statusSummary(1)]), response(statusRows(1)), response([privateRow]));
  await assert.rejects(() => new CloudRepository({ client: privateClient }).listTasks("active"), CloudRepositoryDataError);

  const inconsistent = taskRow("task-bad", "2026-07-28T00:00:03Z");
  inconsistent.event_count = 1;
  const inconsistentClient = new FakeClient(response([statusSummary(1)]), response(statusRows(1)), response([inconsistent]));
  await assert.rejects(() => new CloudRepository({ client: inconsistentClient }).listTasks("active"), CloudRepositoryDataError);
});

test("surfaces a remote outage without inventing local readiness", async () => {
  const outage = new Error("D1 unavailable");
  await assert.rejects(() => new CloudRepository({ client: new FakeClient(outage) }).getStatus(), outage);
});

test("assembles one visible task publication as an all-or-nothing detail graph", async () => {
  const client = new FakeClient(...detailResponses());
  const detail = await new CloudRepository({ client }).getTaskDetail(detailTaskId);
  assert(detail);
  assert.equal(detail.task.taskId, detailTaskId);
  assert.equal(detail.task.pipelineId, detailPipelineId);
  assert.equal(detail.task.completedRunId, detailRunId);
  assert.deepEqual(detail.pipelines.map((pipeline) => pipeline.pipelineId), [detailPipelineId]);
  assert.deepEqual(detail.runs.map((run) => run.runId), [detailRunId]);
  assert.deepEqual(detail.events.map((event) => event.sequence), [1, 2]);
  assert.equal(detail.artifacts[0]!.logicalPath, "runs/run-detail/trajectory.json");
  assert.equal(detail.trajectory?.artifactId, "artifact-atif");
  assert.deepEqual(client.calls.map((call) => call.statement), [
    TASK_DETAIL_STATEMENT,
    TASK_DETAIL_PIPELINES_STATEMENT,
    TASK_DETAIL_RUNS_STATEMENT,
    TASK_DETAIL_EVENTS_STATEMENT,
    TASK_DETAIL_ARTIFACTS_STATEMENT,
  ]);
  assert.equal(client.calls[1]!.params.at(-1), 2);
  assert.equal(client.calls[2]!.params.at(-1), 2);
  assert.equal(client.calls[3]!.params.at(-1), 3);
  assert.equal(client.calls[4]!.params.at(-1), 2);
});

test("keeps an active-after-planning task complete while exposing its completed trajectory", async () => {
  const detail = await new CloudRepository({ client: new FakeClient(...detailResponses({ lifecycleState: "active" })) }).loadTaskDetail(detailTaskId);
  assert(detail);
  assert.equal(detail.task.lifecycleState, "active");
  assert.equal(detail.task.completedAt, null);
  assert.equal(detail.task.completedRunId, detailRunId);
  assert(detail.trajectory);
  const descriptor = await new CloudRepository({ client: new FakeClient(...detailResponses({ lifecycleState: "active" })) }).getTrajectoryDescriptor(detailTaskId, detailRunId);
  assert.equal(descriptor?.runId, detailRunId);
});

test("returns no detail for an absent or hidden publication but rejects dangling and excessive graphs", async () => {
  const absent = await new CloudRepository({ client: new FakeClient(response([])) }).getTaskDetail(detailTaskId);
  assert.equal(absent, null);

  const excessivePipelines = detailResponses();
  excessivePipelines[1] = response([detailPipelineRow(), { ...detailPipelineRow(), pipeline_id: "pipeline-extra" }]);
  await assert.rejects(
    () => new CloudRepository({ client: new FakeClient(...excessivePipelines) }).getTaskDetail(detailTaskId),
    CloudRepositoryDataError,
  );

  const dangling = detailResponses();
  dangling[2] = response([{ ...detailRunRow(), pipeline_id: "pipeline-missing" }]);
  await assert.rejects(
    () => new CloudRepository({ client: new FakeClient(...dangling) }).getTaskDetail(detailTaskId),
    CloudRepositoryDataError,
  );
});

test("rejects a visible head and generation when the required task row is missing", async () => {
  const danglingTask = detailTaskRow();
  danglingTask.task_id = null;
  danglingTask.title = null;
  danglingTask.lifecycle_state = null;
  danglingTask.created_at = null;
  danglingTask.completed_at = null;
  const client = new FakeClient(response([danglingTask]));

  await assert.rejects(
    () => new CloudRepository({ client }).getTaskDetail(detailTaskId),
    CloudRepositoryDataError,
  );
  assert.equal(client.calls.length, 1);
  assert.match(client.calls[0]!.statement, /LEFT JOIN tasks AS t/);
  assert.match(client.calls[0]!.statement, /p\.task_id = \?/);
});

test("selects only visible logical artifacts and resolves a validated anonymous URL", async () => {
  const config = {
    accountId: "a".repeat(32),
    databaseId: "00000000-0000-0000-0000-000000000001",
    d1ReadToken: "read-token",
    publicR2BaseUrl: "https://objects.example.test/public/",
  };
  const client = new FakeClient(response([detailArtifactRow()]));
  const descriptor = await new CloudRepository({ client, config }).getArtifactDescriptor(detailTaskId, "runs/run-detail/trajectory.json");
  assert(descriptor);
  assert.equal(descriptor.mediaType, "application/json");
  assert.equal(descriptor.publicUrl, `https://objects.example.test/public/${detailPublicKey}`);
  assert.equal(client.calls[0]!.statement, ARTIFACT_DESCRIPTOR_STATEMENT);

  const unknown = await new CloudRepository({ client: new FakeClient(response([])), config }).getArtifactDescriptor(detailTaskId, "runs/run-detail/missing.txt");
  assert.equal(unknown, null);
  const unsafePath = await new CloudRepository({ client: new FakeClient(response([])), config }).getArtifactDescriptor(detailTaskId, "../private.txt");
  assert.equal(unsafePath, null);

  const unsafeKey = detailArtifactRow();
  unsafeKey.public_key = "private://object";
  await assert.rejects(
    () => new CloudRepository({ client: new FakeClient(response([unsafeKey])), config }).getArtifactDescriptor(detailTaskId, "runs/run-detail/trajectory.json"),
    CloudRepositoryDataError,
  );
});

test("does not expose a trajectory when the canonical ATIF artifact is unavailable", async () => {
  const detail = await new CloudRepository({ client: new FakeClient(...detailResponses({ availability: "unavailable" })) }).getTaskDetail(detailTaskId);
  assert(detail);
  assert.equal(detail.trajectory, null);
  const descriptor = await new CloudRepository({ client: new FakeClient(...detailResponses({ availability: "unavailable" })) }).getTrajectoryDescriptor(detailTaskId);
  assert.equal(descriptor, null);
});

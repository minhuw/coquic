import "server-only";

import type { CloudReaderConfig } from "./cloud-config";
import { getCloudReaderConfig } from "./cloud-config";
import {
  createCloudflareD1Client,
  type D1ClientOptions,
  type D1QueryResponse,
  type D1Scalar,
} from "./cloudflare";
import {
  decodePublicationCursor,
  encodePublicationCursor,
  PublicationCursorError,
  type PublicationCursor,
} from "./publication";
import {
  validateCloudStatusData,
  validateCloudTaskSummary,
  type CloudStatus,
  type CloudTaskSummary,
} from "./cloud-schema";

export type CloudTaskScope = "active" | "history";

export interface CloudD1QueryClient {
  query(statement: string, params?: readonly D1Scalar[]): Promise<D1QueryResponse>;
}

export interface CloudTaskPage {
  readonly tasks: readonly CloudTaskSummary[];
  readonly nextCursor: string | null;
  readonly previousCursor: string | null;
  readonly total: number;
}

export interface CloudTaskListOptions {
  readonly scope: CloudTaskScope;
  readonly cursor?: string | null;
  readonly limit?: number;
}

export interface CloudRepositoryOptions {
  readonly client?: CloudD1QueryClient;
  readonly config?: CloudReaderConfig;
  readonly d1Options?: D1ClientOptions;
}

export class CloudRepositoryDataError extends Error {
  readonly code = "INVALID_PUBLIC_DATA";

  constructor() {
    super("invalid visible Steward cloud data");
    this.name = "CloudRepositoryDataError";
  }
}

const MAX_PAGE_SIZE = 50;
const MAX_COUNT = 1_000_000;
const ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const TIMESTAMP = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?Z$/;

/** The latest visible generation is the publication snapshot used by cursors. */
export const STATUS_STATEMENT = `
SELECT
  COUNT(*) AS task_count,
  MAX(p.exposed_at) AS latest_publication_at,
  (
    SELECT p2.publication_id
      FROM task_heads AS h2
      JOIN publication_generations AS p2
        ON p2.publication_id = h2.publication_id
       AND p2.task_id = h2.task_id
       AND p2.state = 'visible'
       AND p2.exposed_at IS NOT NULL
      JOIN tasks AS t2
        ON t2.publication_id = p2.publication_id
       AND t2.task_id = h2.task_id
     WHERE h2.state = 'visible'
     ORDER BY p2.exposed_at DESC, p2.publication_id DESC
     LIMIT 1
  ) AS latest_publication_id
  FROM task_heads AS h
  JOIN publication_generations AS p
    ON p.publication_id = h.publication_id
   AND p.task_id = h.task_id
   AND p.state = 'visible'
   AND p.exposed_at IS NOT NULL
  JOIN tasks AS t
    ON t.publication_id = p.publication_id
   AND t.task_id = h.task_id
 WHERE h.state = 'visible'
`;

const TASK_COLUMNS = `
  h.updated_at AS head_updated_at,
  p.publication_id AS publication_id,
  t.task_id AS task_id,
  t.title AS title,
  t.lifecycle_state AS lifecycle_state,
  t.created_at AS created_at,
  t.completed_at AS completed_at,
  p.expected_event_count AS expected_event_count,
  p.expected_artifact_count AS expected_artifact_count,
  COUNT(DISTINCT e.sequence) AS event_count,
  COUNT(DISTINCT a.artifact_id) AS artifact_count,
  r.pipeline_id AS pipeline_id,
  r.run_id AS run_id,
  r.run_state AS run_state,
  MIN(a.redaction_applied) AS redaction_applied_min,
  MAX(a.redaction_applied) AS redaction_applied_max,
  MIN(a.original_retained) AS original_retained_min,
  MAX(a.original_retained) AS original_retained_max
`;

const TASK_FROM = `
  FROM task_heads AS h
  JOIN publication_generations AS p
    ON p.publication_id = h.publication_id
   AND p.task_id = h.task_id
   AND p.state = 'visible'
   AND p.exposed_at IS NOT NULL
  JOIN tasks AS t
    ON t.publication_id = p.publication_id
   AND t.task_id = h.task_id
  JOIN runs AS r
    ON r.publication_id = p.publication_id
   AND r.task_id = h.task_id
   AND r.run_id = p.run_id
  JOIN pipelines AS pl
    ON pl.publication_id = p.publication_id
   AND pl.task_id = t.task_id
   AND pl.pipeline_id = r.pipeline_id
  LEFT JOIN task_events AS e
    ON e.publication_id = p.publication_id
   AND e.task_id = t.task_id
  LEFT JOIN artifacts AS a
    ON a.publication_id = p.publication_id
   AND a.task_id = t.task_id
   AND a.run_id = r.run_id
 WHERE h.state = 'visible'
`;

const TASK_GROUP = `
 GROUP BY h.updated_at, p.publication_id, t.task_id, t.title,
          t.lifecycle_state, t.created_at, t.completed_at,
          p.expected_event_count, p.expected_artifact_count,
          r.pipeline_id, r.run_id, r.run_state
`;

export const ACTIVE_PAGE_FIRST_STATEMENT = `
SELECT${TASK_COLUMNS}${TASK_FROM}
  AND t.lifecycle_state = 'active'
${TASK_GROUP}
 ORDER BY h.updated_at DESC, t.task_id DESC
 LIMIT ?
`;

export const ACTIVE_PAGE_NEXT_STATEMENT = `
SELECT${TASK_COLUMNS}${TASK_FROM}
  AND t.lifecycle_state = 'active'
  AND (h.updated_at < ? OR (h.updated_at = ? AND t.task_id < ?))
${TASK_GROUP}
 ORDER BY h.updated_at DESC, t.task_id DESC
 LIMIT ?
`;

export const ACTIVE_PAGE_PREVIOUS_STATEMENT = `
SELECT${TASK_COLUMNS}${TASK_FROM}
  AND t.lifecycle_state = 'active'
  AND (h.updated_at > ? OR (h.updated_at = ? AND t.task_id > ?))
${TASK_GROUP}
 ORDER BY h.updated_at ASC, t.task_id ASC
 LIMIT ?
`;

export const HISTORY_PAGE_FIRST_STATEMENT = `
SELECT${TASK_COLUMNS}${TASK_FROM}
  AND t.lifecycle_state IN ('completed', 'failed', 'cancelled')
${TASK_GROUP}
 ORDER BY h.updated_at DESC, t.task_id DESC
 LIMIT ?
`;

export const HISTORY_PAGE_NEXT_STATEMENT = `
SELECT${TASK_COLUMNS}${TASK_FROM}
  AND t.lifecycle_state IN ('completed', 'failed', 'cancelled')
  AND (h.updated_at < ? OR (h.updated_at = ? AND t.task_id < ?))
${TASK_GROUP}
 ORDER BY h.updated_at DESC, t.task_id DESC
 LIMIT ?
`;

export const HISTORY_PAGE_PREVIOUS_STATEMENT = `
SELECT${TASK_COLUMNS}${TASK_FROM}
  AND t.lifecycle_state IN ('completed', 'failed', 'cancelled')
  AND (h.updated_at > ? OR (h.updated_at = ? AND t.task_id > ?))
${TASK_GROUP}
 ORDER BY h.updated_at ASC, t.task_id ASC
 LIMIT ?
`;

export const ACTIVE_COUNT_STATEMENT = `
SELECT COUNT(DISTINCT t.task_id) AS task_count
${TASK_FROM}
  AND t.lifecycle_state = 'active'
`;

export const HISTORY_COUNT_STATEMENT = `
SELECT COUNT(DISTINCT t.task_id) AS task_count
${TASK_FROM}
  AND t.lifecycle_state IN ('completed', 'failed', 'cancelled')
`;

export const ACTIVE_CURSOR_STATEMENT = `
SELECT h.updated_at AS head_updated_at, t.task_id AS task_id
${TASK_FROM}
  AND t.lifecycle_state = 'active'
  AND h.updated_at = ?
  AND t.task_id = ?
 LIMIT 1
`;

export const HISTORY_CURSOR_STATEMENT = `
SELECT h.updated_at AS head_updated_at, t.task_id AS task_id
${TASK_FROM}
  AND t.lifecycle_state IN ('completed', 'failed', 'cancelled')
  AND h.updated_at = ?
  AND t.task_id = ?
 LIMIT 1
`;

const SCOPE_QUERY: Record<CloudTaskScope, string> = {
  active: "tasks-active",
  history: "tasks-history",
};

const PAGE_STATEMENTS: Record<CloudTaskScope, Record<"first" | "next" | "previous", string>> = {
  active: { first: ACTIVE_PAGE_FIRST_STATEMENT, next: ACTIVE_PAGE_NEXT_STATEMENT, previous: ACTIVE_PAGE_PREVIOUS_STATEMENT },
  history: { first: HISTORY_PAGE_FIRST_STATEMENT, next: HISTORY_PAGE_NEXT_STATEMENT, previous: HISTORY_PAGE_PREVIOUS_STATEMENT },
};

const COUNT_STATEMENTS: Record<CloudTaskScope, string> = { active: ACTIVE_COUNT_STATEMENT, history: HISTORY_COUNT_STATEMENT };
const CURSOR_STATEMENTS: Record<CloudTaskScope, string> = { active: ACTIVE_CURSOR_STATEMENT, history: HISTORY_CURSOR_STATEMENT };

type CursorDirection = "next" | "previous";
type DecodedTaskCursor = { direction: CursorDirection; updatedAt: string; taskId: string };

const STATUS_KEYS = ["task_count", "latest_publication_at", "latest_publication_id"] as const;
const TASK_KEYS = [
  "head_updated_at", "publication_id", "task_id", "title", "lifecycle_state", "created_at", "completed_at",
  "expected_event_count", "expected_artifact_count", "event_count", "artifact_count", "pipeline_id", "run_id", "run_state",
  "redaction_applied_min", "redaction_applied_max", "original_retained_min", "original_retained_max",
] as const;
const COUNT_KEYS = ["task_count"] as const;
const CURSOR_KEYS = ["head_updated_at", "task_id"] as const;

function invalidData(): never {
  throw new CloudRepositoryDataError();
}

function record(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) invalidData();
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) invalidData();
  return value as Record<string, unknown>;
}

function isClient(value: unknown): value is CloudD1QueryClient {
  return Boolean(value) && typeof value === "object" && typeof (value as { query?: unknown }).query === "function";
}

function isConfig(value: unknown): value is CloudReaderConfig {
  return Boolean(value)
    && typeof value === "object"
    && typeof (value as { accountId?: unknown }).accountId === "string"
    && typeof (value as { databaseId?: unknown }).databaseId === "string"
    && typeof (value as { d1ReadToken?: unknown }).d1ReadToken === "string"
    && typeof (value as { publicR2BaseUrl?: unknown }).publicR2BaseUrl === "string";
}

function exactRow(value: unknown, keys: readonly string[]): Record<string, unknown> {
  const row = record(value);
  const actual = Object.keys(row);
  if (actual.length !== keys.length || actual.some((key) => !keys.includes(key))) invalidData();
  return row;
}

function rowsFromResponse(response: unknown): readonly Record<string, unknown>[] {
  const envelope = record(response);
  if (Object.keys(envelope).length !== 1 || !Array.isArray(envelope.result) || envelope.result.length !== 1) invalidData();
  const resultSet = record(envelope.result[0]);
  if (Object.keys(resultSet).length !== 2 || !Array.isArray(resultSet.results) || !record(resultSet.meta)) invalidData();
  return resultSet.results.map((row) => record(row));
}

function boundedInteger(value: unknown, maximum: number): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0 || value > maximum) invalidData();
  return value;
}

function id(value: unknown): string {
  if (typeof value !== "string" || !ID.test(value)) invalidData();
  return value;
}

function timestamp(value: unknown): string {
  if (typeof value !== "string" || !TIMESTAMP.test(value)) invalidData();
  try {
    validateCloudStatusData({ state: "empty", taskCount: 0, latestPublicationAt: value });
  } catch {
    invalidData();
  }
  return value;
}

function nullableTimestamp(value: unknown): string | null {
  return value === null ? null : timestamp(value);
}

function disclosure(value: unknown): boolean {
  if (value === true || value === 1) return true;
  if (value === false || value === 0) return false;
  invalidData();
}

function parseStatus(rowValue: unknown): { status: CloudStatus; publicationId: string | null } {
  const row = exactRow(rowValue, STATUS_KEYS);
  const taskCount = boundedInteger(row.task_count, MAX_COUNT);
  const latestPublicationAt = nullableTimestamp(row.latest_publication_at);
  const publicationId = row.latest_publication_id === null ? null : id(row.latest_publication_id);
  if (taskCount === 0 && (latestPublicationAt !== null || publicationId !== null)) invalidData();
  if (taskCount > 0 && (latestPublicationAt === null || publicationId === null)) invalidData();
  const status = validateCloudStatusData({
    state: taskCount === 0 ? "empty" : "available",
    taskCount,
    latestPublicationAt,
  });
  return { status, publicationId };
}

function parseTask(rowValue: unknown): { task: CloudTaskSummary; updatedAt: string } {
  const row = exactRow(rowValue, TASK_KEYS);
  const updatedAt = timestamp(row.head_updated_at);
  const publicationId = id(row.publication_id);
  const taskId = id(row.task_id);
  const pipelineId = id(row.pipeline_id);
  const runId = id(row.run_id);
  const runState = row.run_state;
  if (runState !== "completed" && runState !== "failed" && runState !== "cancelled") invalidData();
  const completedRunId = runState === "completed" ? runId : null;
  const expectedEventCount = boundedInteger(row.expected_event_count, MAX_COUNT);
  const expectedArtifactCount = boundedInteger(row.expected_artifact_count, MAX_COUNT);
  const eventCount = boundedInteger(row.event_count, MAX_COUNT);
  const artifactCount = boundedInteger(row.artifact_count, MAX_COUNT);
  if (expectedEventCount !== eventCount || expectedArtifactCount !== artifactCount || expectedArtifactCount === 0) invalidData();
  const redactionMin = disclosure(row.redaction_applied_min);
  const redactionMax = disclosure(row.redaction_applied_max);
  const originalMin = disclosure(row.original_retained_min);
  const originalMax = disclosure(row.original_retained_max);
  if (redactionMin !== redactionMax || originalMin !== originalMax) invalidData();
  const task = validateCloudTaskSummary({
    taskId,
    title: row.title,
    lifecycleState: row.lifecycle_state,
    createdAt: row.created_at,
    completedAt: row.completed_at,
    completeness: "complete",
    pipelineId,
    completedRunId,
    eventCount,
    artifactCount,
    disclosure: { redactionApplied: redactionMin, originalRetained: originalMin },
  });
  if (publicationId.length === 0) invalidData();
  return { task, updatedAt };
}

function parseCount(rowValue: unknown): number {
  const row = exactRow(rowValue, COUNT_KEYS);
  return boundedInteger(row.task_count, MAX_COUNT);
}

function parseCursorBoundary(rowValue: unknown, expected: DecodedTaskCursor): void {
  const row = exactRow(rowValue, CURSOR_KEYS);
  if (timestamp(row.head_updated_at) !== expected.updatedAt || id(row.task_id) !== expected.taskId) invalidData();
}

function cursorError(code: "INVALID_CURSOR" | "STALE_CURSOR"): never {
  throw new PublicationCursorError(code, code === "STALE_CURSOR" ? "cursor is stale" : "invalid cursor");
}

function decodeTaskCursor(value: unknown, scope: CloudTaskScope, publicationId: string): DecodedTaskCursor {
  let cursor: PublicationCursor;
  try {
    cursor = decodePublicationCursor(value, { query: SCOPE_QUERY[scope], publicationId });
  } catch (error) {
    if (error instanceof PublicationCursorError) throw error;
    cursorError("INVALID_CURSOR");
  }
  if (cursor.sort.length !== 3 || typeof cursor.sort[0] !== "string" || typeof cursor.sort[1] !== "string" || typeof cursor.sort[2] !== "string") cursorError("INVALID_CURSOR");
  const updatedAt = cursor.sort[0];
  const taskId = cursor.sort[1];
  const direction = cursor.sort[2];
  if (!TIMESTAMP.test(updatedAt) || !ID.test(taskId) || (direction !== "next" && direction !== "previous")) cursorError("INVALID_CURSOR");
  return { direction, updatedAt, taskId };
}

function boundedLimit(value: unknown): number {
  if (value === undefined) return MAX_PAGE_SIZE;
  if (typeof value !== "number" || Number.isNaN(value)) return MAX_PAGE_SIZE;
  if (!Number.isFinite(value)) return value > 0 ? MAX_PAGE_SIZE : 1;
  return Math.min(MAX_PAGE_SIZE, Math.max(1, Math.trunc(value)));
}

function parseListArguments(
  scopeOrOptions: CloudTaskScope | CloudTaskListOptions,
  optionsOrCursor?: CloudTaskListOptions | string | null,
  limit?: number,
): { scope: CloudTaskScope; cursor: string | null; limit: number } {
  if (typeof scopeOrOptions === "object") {
    if (scopeOrOptions.scope !== "active" && scopeOrOptions.scope !== "history") invalidData();
    return { scope: scopeOrOptions.scope, cursor: scopeOrOptions.cursor ?? null, limit: boundedLimit(scopeOrOptions.limit) };
  }
  if (scopeOrOptions !== "active" && scopeOrOptions !== "history") invalidData();
  if (typeof optionsOrCursor === "object" && optionsOrCursor !== null) {
    return { scope: scopeOrOptions, cursor: optionsOrCursor.cursor ?? null, limit: boundedLimit(optionsOrCursor.limit) };
  }
  return { scope: scopeOrOptions, cursor: optionsOrCursor ?? null, limit: boundedLimit(limit) };
}

export class CloudRepository {
  private readonly configuredClient: CloudD1QueryClient | undefined;
  private readonly configuredConfig: CloudReaderConfig | undefined;
  private readonly d1Options: D1ClientOptions;
  private runtimeClient: CloudD1QueryClient | undefined;

  constructor(options?: CloudRepositoryOptions | CloudD1QueryClient | CloudReaderConfig, config?: CloudReaderConfig) {
    if (isClient(options)) {
      this.configuredClient = options as CloudD1QueryClient;
      this.configuredConfig = config;
      this.d1Options = {};
    } else if (isConfig(options)) {
      this.configuredClient = undefined;
      this.configuredConfig = options;
      this.d1Options = {};
    } else {
      const resolved = (options ?? {}) as CloudRepositoryOptions;
      this.configuredClient = resolved.client;
      this.configuredConfig = resolved.config;
      this.d1Options = resolved.d1Options ?? {};
    }
  }

  private client(): CloudD1QueryClient {
    if (this.configuredClient) return this.configuredClient;
    if (!this.runtimeClient) this.runtimeClient = createCloudflareD1Client(this.configuredConfig ?? getCloudReaderConfig(), this.d1Options);
    return this.runtimeClient;
  }

  private async readStatus(): Promise<{ status: CloudStatus; publicationId: string | null }> {
    const response = await this.client().query(STATUS_STATEMENT, []);
    const rows = rowsFromResponse(response);
    if (rows.length !== 1) invalidData();
    return parseStatus(rows[0]);
  }

  async getStatus(): Promise<CloudStatus> {
    return (await this.readStatus()).status;
  }

  async listTasks(scope: CloudTaskScope, options?: Omit<CloudTaskListOptions, "scope">): Promise<CloudTaskPage>;
  async listTasks(options: CloudTaskListOptions): Promise<CloudTaskPage>;
  async listTasks(scope: CloudTaskScope, cursor?: string | null, limit?: number): Promise<CloudTaskPage>;
  async listTasks(
    scopeOrOptions: CloudTaskScope | CloudTaskListOptions,
    optionsOrCursor?: Omit<CloudTaskListOptions, "scope"> | string | null,
    limit?: number,
  ): Promise<CloudTaskPage> {
    const args = parseListArguments(scopeOrOptions, optionsOrCursor as CloudTaskListOptions | string | null | undefined, limit);
    const snapshot = await this.readStatus();
    if (snapshot.status.taskCount === 0) return { tasks: [], nextCursor: null, previousCursor: null, total: 0 };
    if (!snapshot.publicationId) invalidData();

    const cursor = args.cursor === null ? null : decodeTaskCursor(args.cursor, args.scope, snapshot.publicationId);
    if (cursor) {
      const boundaryResponse = await this.client().query(CURSOR_STATEMENTS[args.scope], [cursor.updatedAt, cursor.taskId]);
      const boundaryRows = rowsFromResponse(boundaryResponse);
      if (boundaryRows.length !== 1) cursorError("STALE_CURSOR");
      parseCursorBoundary(boundaryRows[0], cursor);
    }

    const statement = cursor ? PAGE_STATEMENTS[args.scope][cursor.direction] : PAGE_STATEMENTS[args.scope].first;
    const queryParams: D1Scalar[] = cursor ? [cursor.updatedAt, cursor.updatedAt, cursor.taskId, args.limit + 1] : [args.limit + 1];
    const pageResponse = await this.client().query(statement, queryParams);
    const pageRows = rowsFromResponse(pageResponse);
    if (pageRows.length > args.limit + 1) invalidData();
    const parsedRows = pageRows.map(parseTask);
    const hasExtra = parsedRows.length > args.limit;
    const pageRowsForOutput = cursor?.direction === "previous"
      ? parsedRows.slice(0, args.limit).reverse()
      : parsedRows.slice(0, args.limit);
    const countResponse = await this.client().query(COUNT_STATEMENTS[args.scope], []);
    const countRows = rowsFromResponse(countResponse);
    if (countRows.length !== 1) invalidData();
    const total = parseCount(countRows[0]);
    if (total < pageRowsForOutput.length) invalidData();
    const seen = new Set<string>();
    for (const item of pageRowsForOutput) {
      if (seen.has(item.task.taskId)) invalidData();
      seen.add(item.task.taskId);
    }

    const first = pageRowsForOutput[0];
    const last = pageRowsForOutput.at(-1);
    let nextCursor: string | null = null;
    let previousCursor: string | null = null;
    if (first && (cursor?.direction === "previous" ? hasExtra : false)) {
      previousCursor = encodePublicationCursor({ query: SCOPE_QUERY[args.scope], publicationId: snapshot.publicationId, sort: [first.updatedAt, first.task.taskId, "previous"] });
    } else if (first && cursor?.direction === "next") {
      previousCursor = encodePublicationCursor({ query: SCOPE_QUERY[args.scope], publicationId: snapshot.publicationId, sort: [first.updatedAt, first.task.taskId, "previous"] });
    }
    if (last && (cursor?.direction === "next" || !cursor) && hasExtra) {
      nextCursor = encodePublicationCursor({ query: SCOPE_QUERY[args.scope], publicationId: snapshot.publicationId, sort: [last.updatedAt, last.task.taskId, "next"] });
    } else if (last && cursor?.direction === "previous") {
      nextCursor = encodePublicationCursor({ query: SCOPE_QUERY[args.scope], publicationId: snapshot.publicationId, sort: [last.updatedAt, last.task.taskId, "next"] });
    }
    return { tasks: pageRowsForOutput.map((item) => item.task), nextCursor, previousCursor, total };
  }

  async listActiveTasks(options?: Omit<CloudTaskListOptions, "scope">): Promise<CloudTaskPage> {
    return this.listTasks("active", options);
  }

  async listHistoryTasks(options?: Omit<CloudTaskListOptions, "scope">): Promise<CloudTaskPage> {
    return this.listTasks("history", options);
  }
}

let repository: CloudRepository | null = null;

export function createCloudRepository(options?: CloudRepositoryOptions | CloudD1QueryClient | CloudReaderConfig, config?: CloudReaderConfig): CloudRepository {
  return new CloudRepository(options, config);
}

export function getCloudRepository(config?: CloudReaderConfig | CloudRepositoryOptions | CloudD1QueryClient, d1Options: D1ClientOptions = {}): CloudRepository {
  if (!repository) {
    if (isClient(config) || isConfig(config)) repository = new CloudRepository(config);
    else repository = new CloudRepository({ ...(config ?? {}), d1Options });
  }
  return repository;
}

export function resetCloudRepository(): void {
  repository = null;
}

export {
  CloudRepository as CloudStewardArchiveRepository,
  CloudRepository as StewardCloudRepository,
  createCloudRepository as createCloudStewardArchiveRepository,
  getCloudRepository as getCloudStewardArchiveRepository,
  decodePublicationCursor,
  encodePublicationCursor,
  PublicationCursorError,
};

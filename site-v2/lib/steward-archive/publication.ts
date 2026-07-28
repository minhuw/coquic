export type DisclosureFlag = boolean | 0 | 1;
export type PublicationState = "visible";
export type TaskLifecycle = "active" | "completed" | "failed" | "cancelled";
export type RunState = "completed" | "failed" | "cancelled";

export interface PublicGeneration {
  publication_id: string; task_id: string; run_id: string; metadata_digest: string; idempotency_key: string;
  state: PublicationState; expected_task_count: number; expected_pipeline_count: number; expected_run_count: number;
  expected_event_count: number; expected_artifact_count: number; created_at: string; exposed_at: string;
}
export interface PublicHead { task_id: string; publication_id: string; state: PublicationState; updated_at: string; }
export interface PublicTask { publication_id: string; task_id: string; title: string; lifecycle_state: TaskLifecycle; created_at: string; completed_at: string | null; }
export interface PublicPipeline { publication_id: string; pipeline_id: string; task_id: string; name: string; created_at: string; }
export interface PublicRun { publication_id: string; run_id: string; task_id: string; pipeline_id: string; role: string; run_state: RunState; started_at: string; completed_at: string; duration_ms: number; atif_digest: string; }
export interface PublicEvent { publication_id: string; task_id: string; sequence: number; event_type: string; occurred_at: string; summary: string; }
export interface PublicArtifact {
  publication_id: string; artifact_id: string; task_id: string; run_id: string; logical_path: string; public_key: string;
  media_type: string; byte_size: number; sha256: string; availability: "available" | "unavailable";
  redaction_applied: DisclosureFlag; original_retained: DisclosureFlag;
}
export interface PublicPublicationRows {
  generation: PublicGeneration; head: PublicHead; task: PublicTask; pipelines: PublicPipeline[];
  runs: PublicRun[]; events: PublicEvent[]; artifacts: PublicArtifact[];
}

export class PublicationValidationError extends Error {
  readonly code = "INVALID_PUBLICATION";
  constructor(path: string, reason = "invalid public publication") { super(`${reason} at ${path}`); this.name = "PublicationValidationError"; }
}
export type CursorErrorCode = "INVALID_CURSOR" | "STALE_CURSOR";
export class PublicationCursorError extends Error {
  readonly code: CursorErrorCode;
  constructor(code: CursorErrorCode, message: string) { super(message); this.name = "PublicationCursorError"; this.code = code; }
}

const ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const DIGEST = /^[0-9a-f]{64}$/;
const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/;
const PRIVATE_NAME = /(?:private|secret|credential|password|authorization|presign|signed|scanner|filesystem|file[_-]?path|endpoint|uri|url|bucket|object[_-]?key|token)/i;
const LOCATOR = /(?:^[a-z][a-z0-9+.-]*:\/\/|^\/(?:[^/]|$)|^[A-Za-z]:[\\/])/i;
const KEY = /^v1\/tasks\/([A-Za-z0-9][A-Za-z0-9._-]{0,127})\/objects\/sha256\/([0-9a-f]{2})\/([0-9a-f]{64})$/;

function fail(path: string, reason?: string): never { throw new PublicationValidationError(path, reason); }
function object(value: unknown, path: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail(path, "expected object");
  const proto = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null) fail(path, "expected plain object");
  return value as Record<string, unknown>;
}
function exact(value: unknown, keys: readonly string[], path: string): Record<string, unknown> {
  const row = object(value, path); const actual = Object.keys(row);
  if (actual.length !== keys.length || actual.some((key) => !keys.includes(key))) fail(path, "unexpected public fields");
  return row;
}
function privateScan(value: unknown, path: string): void {
  if (typeof value === "string") { if (LOCATOR.test(value)) fail(path, "private locator"); return; }
  if (Array.isArray(value)) { value.forEach((item, index) => privateScan(item, `${path}[${index}]`)); return; }
  if (!value || typeof value !== "object") return;
  for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
    if (PRIVATE_NAME.test(key) && key !== "logical_path" && key !== "public_key") fail(`${path}.${key}`, "private-shaped field");
    privateScan(item, `${path}.${key}`);
  }
}
function checked(value: unknown, path: string, max: number, min = 1): string {
  if (typeof value !== "string" || value.length < min || value.length > max || value.includes("\0")) fail(path, "invalid text");
  return value;
}
function id(value: unknown, path: string): string { if (typeof value !== "string" || !ID.test(value)) fail(path, "invalid id"); return value; }
function digest(value: unknown, path: string): string { if (typeof value !== "string" || !DIGEST.test(value)) fail(path, "invalid digest"); return value; }
function timestamp(value: unknown, path: string): string {
  if (typeof value !== "string" || !TIMESTAMP.test(value) || !Number.isFinite(Date.parse(value))) fail(path, "invalid UTC timestamp");
  return value;
}
function integer(value: unknown, path: string): number { if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) fail(path, "invalid nonnegative integer"); return value; }
function flag(value: unknown, path: string): DisclosureFlag {
  if (typeof value === "boolean" || value === 0 || value === 1) return value;
  fail(path, "invalid disclosure flag");
}
function same(left: string, right: string, path: string): void { if (left !== right) fail(path, "relationship mismatch"); }
function timeOrder(start: string, end: string, path: string): void { if (Date.parse(end) < Date.parse(start)) fail(path, "timestamp order"); }

export function validatePublicGeneration(value: unknown): PublicGeneration {
  const row = exact(value, ["publication_id", "task_id", "run_id", "metadata_digest", "idempotency_key", "state", "expected_task_count", "expected_pipeline_count", "expected_run_count", "expected_event_count", "expected_artifact_count", "created_at", "exposed_at"], "generation");
  privateScan(row, "generation");
  const result = {
    publication_id: id(row.publication_id, "generation.publication_id"), task_id: id(row.task_id, "generation.task_id"), run_id: id(row.run_id, "generation.run_id"),
    metadata_digest: digest(row.metadata_digest, "generation.metadata_digest"), idempotency_key: id(row.idempotency_key, "generation.idempotency_key"), state: row.state,
    expected_task_count: integer(row.expected_task_count, "generation.expected_task_count"), expected_pipeline_count: integer(row.expected_pipeline_count, "generation.expected_pipeline_count"),
    expected_run_count: integer(row.expected_run_count, "generation.expected_run_count"), expected_event_count: integer(row.expected_event_count, "generation.expected_event_count"), expected_artifact_count: integer(row.expected_artifact_count, "generation.expected_artifact_count"),
    created_at: timestamp(row.created_at, "generation.created_at"), exposed_at: timestamp(row.exposed_at, "generation.exposed_at"),
  };
  if (result.state !== "visible") fail("generation.state", "generation is not visible");
  if (result.expected_task_count !== 1) fail("generation.expected_task_count", "one public task required");
  timeOrder(result.created_at, result.exposed_at, "generation.exposed_at");
  return result as PublicGeneration;
}

export function validatePublicHead(value: unknown): PublicHead {
  const row = exact(value, ["task_id", "publication_id", "state", "updated_at"], "head"); privateScan(row, "head");
  const result = { task_id: id(row.task_id, "head.task_id"), publication_id: id(row.publication_id, "head.publication_id"), state: row.state, updated_at: timestamp(row.updated_at, "head.updated_at") };
  if (result.state !== "visible") fail("head.state", "head is not visible");
  return result as PublicHead;
}

export function validatePublicTask(value: unknown): PublicTask {
  const row = exact(value, ["publication_id", "task_id", "title", "lifecycle_state", "created_at", "completed_at"], "task"); privateScan(row, "task");
  const lifecycle = row.lifecycle_state;
  if (lifecycle !== "active" && lifecycle !== "completed" && lifecycle !== "failed" && lifecycle !== "cancelled") fail("task.lifecycle_state", "invalid lifecycle state");
  const result = { publication_id: id(row.publication_id, "task.publication_id"), task_id: id(row.task_id, "task.task_id"), title: checked(row.title, "task.title", 512), lifecycle_state: lifecycle as TaskLifecycle, created_at: timestamp(row.created_at, "task.created_at"), completed_at: row.completed_at === null ? null : timestamp(row.completed_at, "task.completed_at") };
  if ((lifecycle === "active") !== (result.completed_at === null)) fail("task.completed_at", "lifecycle completion mismatch");
  if (result.completed_at) timeOrder(result.created_at, result.completed_at, "task.completed_at");
  return result;
}

export function validatePublicPipeline(value: unknown): PublicPipeline {
  const row = exact(value, ["publication_id", "pipeline_id", "task_id", "name", "created_at"], "pipeline"); privateScan(row, "pipeline");
  return { publication_id: id(row.publication_id, "pipeline.publication_id"), pipeline_id: id(row.pipeline_id, "pipeline.pipeline_id"), task_id: id(row.task_id, "pipeline.task_id"), name: checked(row.name, "pipeline.name", 256), created_at: timestamp(row.created_at, "pipeline.created_at") };
}

export function validatePublicRun(value: unknown): PublicRun {
  const row = exact(value, ["publication_id", "run_id", "task_id", "pipeline_id", "role", "run_state", "started_at", "completed_at", "duration_ms", "atif_digest"], "run"); privateScan(row, "run");
  const runState = row.run_state;
  if (runState !== "completed" && runState !== "failed" && runState !== "cancelled") fail("run.run_state", "invalid terminal state");
  const result = { publication_id: id(row.publication_id, "run.publication_id"), run_id: id(row.run_id, "run.run_id"), task_id: id(row.task_id, "run.task_id"), pipeline_id: id(row.pipeline_id, "run.pipeline_id"), role: checked(row.role, "run.role", 128), run_state: runState as RunState, started_at: timestamp(row.started_at, "run.started_at"), completed_at: timestamp(row.completed_at, "run.completed_at"), duration_ms: integer(row.duration_ms, "run.duration_ms"), atif_digest: digest(row.atif_digest, "run.atif_digest") };
  timeOrder(result.started_at, result.completed_at, "run.completed_at");
  if (result.duration_ms !== Date.parse(result.completed_at) - Date.parse(result.started_at)) fail("run.duration_ms", "duration does not match timestamps");
  return result;
}

export function validatePublicEvent(value: unknown): PublicEvent {
  const row = exact(value, ["publication_id", "task_id", "sequence", "event_type", "occurred_at", "summary"], "event"); privateScan(row, "event");
  const sequence = integer(row.sequence, "event.sequence"); if (sequence < 1) fail("event.sequence", "sequence starts at one");
  return { publication_id: id(row.publication_id, "event.publication_id"), task_id: id(row.task_id, "event.task_id"), sequence, event_type: checked(row.event_type, "event.event_type", 128), occurred_at: timestamp(row.occurred_at, "event.occurred_at"), summary: checked(row.summary, "event.summary", 4096, 0) };
}

export function validatePublicKey(value: unknown, expectedTaskId?: string, expectedDigest?: string): string {
  if (typeof value !== "string") fail("artifact.public_key", "invalid public key");
  const match = KEY.exec(value); if (!match || match[2] !== match[3].slice(0, 2) || (expectedTaskId !== undefined && match[1] !== expectedTaskId) || (expectedDigest !== undefined && match[3] !== expectedDigest)) fail("artifact.public_key", "invalid public key");
  return value;
}

export function validatePublicArtifact(value: unknown): PublicArtifact {
  const row = exact(value, ["publication_id", "artifact_id", "task_id", "run_id", "logical_path", "public_key", "media_type", "byte_size", "sha256", "availability", "redaction_applied", "original_retained"], "artifact"); privateScan(row, "artifact");
  const availability = row.availability;
  if (availability !== "available" && availability !== "unavailable") fail("artifact.availability", "invalid availability");
  const taskId = id(row.task_id, "artifact.task_id"); const sha256 = digest(row.sha256, "artifact.sha256");
  const logicalPath = checked(row.logical_path, "artifact.logical_path", 1024); if (logicalPath.startsWith("/") || logicalPath.includes("..") || logicalPath.includes("://") || [...logicalPath].some((char) => char.charCodeAt(0) < 0x20)) fail("artifact.logical_path", "invalid logical path");
  const mediaType = checked(row.media_type, "artifact.media_type", 128); if (/\s/.test(mediaType)) fail("artifact.media_type", "invalid media type");
  return { publication_id: id(row.publication_id, "artifact.publication_id"), artifact_id: id(row.artifact_id, "artifact.artifact_id"), task_id: taskId, run_id: id(row.run_id, "artifact.run_id"), logical_path: logicalPath, public_key: validatePublicKey(row.public_key, taskId, sha256), media_type: mediaType, byte_size: integer(row.byte_size, "artifact.byte_size"), sha256, availability, redaction_applied: flag(row.redaction_applied, "artifact.redaction_applied"), original_retained: flag(row.original_retained, "artifact.original_retained") };
}

function unique(values: readonly string[], path: string): void { if (new Set(values).size !== values.length) fail(path, "duplicate public identity"); }

export function validatePublicPublication(value: unknown): PublicPublicationRows {
  const root = exact(value, ["generation", "head", "task", "pipelines", "runs", "events", "artifacts"], "publication"); privateScan(root, "publication");
  const generation = validatePublicGeneration(root.generation); const head = validatePublicHead(root.head); const task = validatePublicTask(root.task);
  if (!Array.isArray(root.pipelines) || !Array.isArray(root.runs) || !Array.isArray(root.events) || !Array.isArray(root.artifacts)) fail("publication", "collections required");
  const pipelines = root.pipelines.map((item) => validatePublicPipeline(item)); const runs = root.runs.map((item) => validatePublicRun(item)); const events = root.events.map((item) => validatePublicEvent(item)); const artifacts = root.artifacts.map((item) => validatePublicArtifact(item));
  for (const [name, actual, expected] of [["pipelines", pipelines.length, generation.expected_pipeline_count], ["runs", runs.length, generation.expected_run_count], ["events", events.length, generation.expected_event_count], ["artifacts", artifacts.length, generation.expected_artifact_count] ] as const) if (actual !== expected) fail(`generation.expected_${name.slice(0, -1)}_count`, "row count mismatch");
  same(head.task_id, generation.task_id, "head.task_id"); same(head.publication_id, generation.publication_id, "head.publication_id"); same(task.task_id, generation.task_id, "task.task_id"); same(task.publication_id, generation.publication_id, "task.publication_id");
  if (!runs.some((row) => row.run_id === generation.run_id)) fail("generation.run_id", "dangling run");
  unique(pipelines.map((row) => row.pipeline_id), "pipelines"); unique(runs.map((row) => row.run_id), "runs"); unique(events.map((row) => String(row.sequence)), "events"); unique(artifacts.map((row) => row.artifact_id), "artifacts"); unique(artifacts.map((row) => row.logical_path), "artifacts.logical_path");
  if (events.some((row, index) => row.sequence !== index + 1)) fail("events", "event sequences must be contiguous");
  const pipelineIds = new Set(pipelines.map((row) => { same(row.publication_id, generation.publication_id, "pipeline.publication_id"); same(row.task_id, generation.task_id, "pipeline.task_id"); return row.pipeline_id; }));
  const runIds = new Set(runs.map((row) => { same(row.publication_id, generation.publication_id, "run.publication_id"); same(row.task_id, generation.task_id, "run.task_id"); if (!pipelineIds.has(row.pipeline_id)) fail("run.pipeline_id", "dangling pipeline"); return row.run_id; }));
  for (const row of events) { same(row.publication_id, generation.publication_id, "event.publication_id"); same(row.task_id, generation.task_id, "event.task_id"); }
  const objectSizes = new Map<string, number>();
  for (const row of artifacts) { same(row.publication_id, generation.publication_id, "artifact.publication_id"); same(row.task_id, generation.task_id, "artifact.task_id"); if (!runIds.has(row.run_id)) fail("artifact.run_id", "dangling run"); const prior = objectSizes.get(row.public_key); if (prior !== undefined && prior !== row.byte_size) fail("artifact.byte_size", "conflicting object size"); objectSizes.set(row.public_key, row.byte_size); }
  return { generation, head, task, pipelines, runs, events, artifacts };
}

export const validatePublicationRows = validatePublicPublication;
export const validateGeneration = validatePublicGeneration;
export const validateHead = validatePublicHead;
export const validateTask = validatePublicTask;
export const validatePipeline = validatePublicPipeline;
export const validateRun = validatePublicRun;
export const validateEvent = validatePublicEvent;
export const validateArtifact = validatePublicArtifact;

export type CursorSortValue = string | number | null;
export interface PublicationCursor { version: 1; query: string; publicationId: string; sort: readonly CursorSortValue[]; }
const CURSOR_KEYS = ["version", "query", "publicationId", "sort"] as const;
function cursorQuery(value: unknown): string { if (typeof value !== "string" || !/^[a-z][A-Za-z0-9._-]{0,63}$/.test(value)) throw new PublicationCursorError("INVALID_CURSOR", "invalid cursor"); return value; }
function cursorId(value: unknown): string { if (typeof value !== "string" || !ID.test(value)) throw new PublicationCursorError("INVALID_CURSOR", "invalid cursor"); return value; }
function cursorSort(value: unknown): CursorSortValue[] { if (!Array.isArray(value) || value.length === 0 || value.length > 8 || value.some((item) => !(item === null || (typeof item === "string" && item.length <= 512) || (typeof item === "number" && Number.isSafeInteger(item))))) throw new PublicationCursorError("INVALID_CURSOR", "invalid cursor"); return value as CursorSortValue[]; }
export function encodePublicationCursor(input: { query: string; publicationId: string; sort: readonly CursorSortValue[] }): string {
  const payload: PublicationCursor = { version: 1, query: cursorQuery(input.query), publicationId: cursorId(input.publicationId), sort: cursorSort(input.sort) };
  return Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
}
export function decodePublicationCursor(value: unknown, expected: { query: string; publicationId: string } | string, publicationId?: string): PublicationCursor {
  const expectedQuery = typeof expected === "string" ? expected : expected.query; const expectedPublication = typeof expected === "string" ? publicationId : expected.publicationId;
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)) throw new PublicationCursorError("INVALID_CURSOR", "invalid cursor");
  let payload: unknown;
  try { const raw = Buffer.from(value, "base64url"); if (raw.length === 0 || raw.toString("base64url") !== value) throw new Error(); payload = JSON.parse(raw.toString("utf8")); } catch { throw new PublicationCursorError("INVALID_CURSOR", "invalid cursor"); }
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) throw new PublicationCursorError("INVALID_CURSOR", "invalid cursor");
  const row = payload as Record<string, unknown>; const keys = Object.keys(row);
  if (keys.length !== CURSOR_KEYS.length || keys.some((key) => !CURSOR_KEYS.includes(key as (typeof CURSOR_KEYS)[number]))) throw new PublicationCursorError("INVALID_CURSOR", "invalid cursor");
  if (row.version !== 1 || typeof row.query !== "string" || typeof row.publicationId !== "string") throw new PublicationCursorError("INVALID_CURSOR", "invalid cursor");
  const cursor = { version: 1 as const, query: cursorQuery(row.query), publicationId: cursorId(row.publicationId), sort: cursorSort(row.sort) };
  if (cursor.query !== cursorQuery(expectedQuery) || cursor.publicationId !== cursorId(expectedPublication)) throw new PublicationCursorError("STALE_CURSOR", "cursor is stale");
  return cursor;
}
export const encodeCursor = encodePublicationCursor;
export const decodeCursor = decodePublicationCursor;

export function resolvePublicObjectUrl(base: string, publicKey: string): string {
  validatePublicKey(publicKey);
  let root: URL;
  try { root = new URL(base); } catch { fail("r2_base_url", "invalid public base URL"); }
  if (root.protocol !== "https:" || root.username || root.password || root.search || root.hash) fail("r2_base_url", "invalid public base URL");
  const rawSegments = root.pathname.split("/"); if (rawSegments.some((segment) => segment === "." || segment === "..")) fail("r2_base_url", "invalid public base URL");
  const basePath = root.pathname.endsWith("/") ? root.pathname : `${root.pathname}/`; root.pathname = basePath;
  const segments = publicKey.split("/");
  let resolved: URL;
  try { resolved = new URL(segments.map((segment) => encodeURIComponent(segment)).join("/"), root); } catch { fail("artifact.public_key", "invalid public URL"); }
  if (resolved.origin !== root.origin || !resolved.pathname.startsWith(basePath) || resolved.pathname.slice(basePath.length).split("/").length !== segments.length) fail("artifact.public_key", "public URL escapes base");
  return resolved.toString();
}
export const resolvePublicR2Url = resolvePublicObjectUrl;
export const resolvePublicArtifactUrl = resolvePublicObjectUrl;

import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { open, type FileHandle } from "node:fs/promises";
import { basename } from "node:path";
import { Readable } from "node:stream";
import type { DatabaseSync } from "node:sqlite";
import { getArchiveConfig, type ArchiveConfig } from "./config";
import { getArchiveImporter, type ImportStatus, type StewardArchiveImporter } from "./importer";
import { isSafeId, isSafeRelativePath, resolveDirectoryContainedPath, resolveRegularContainedPath } from "./paths";
import { isRecord, parseCompleteJson, validatePipeline, validateRun, validateTask, validateValidation, validateReview, type JsonRecord } from "./schema";

export type CursorError = Error & { code?: "STALE_CURSOR" | "INVALID_CURSOR" };

export interface TaskRow {
  taskId: string; status: string; title: string; summary: string; currentPipelineId: string | null;
  createdAt: string; updatedAt: string; archiveState: string; lastImportAt: string | null;
}

export interface UsageAggregate {
  tokens: { prompt: number | null; completion: number | null; total: number | null; availableRuns: number; totalRuns: number; promptAvailableRuns: number; completionAvailableRuns: number; totalAvailableRuns: number };
  cost: { microUsd: number | null; availableRuns: number; totalRuns: number };
}

export interface TaskDashboard {
  state: ImportStatus["state"];
  epochId: string | null;
  counts: Record<string, number> & { total: number; indexed: number; verified: number };
  active: TaskRow[];
  recent: TaskRow[];
  usage: UsageAggregate;
  freshness: { lastAttemptAt: string | null; lastSuccessAt: string | null; lagSeconds: number | null; errors: number };
}

export interface TaskPage { tasks: TaskRow[]; nextCursor: string | null; previousCursor: string | null; total: number; revision: number; }

const ACTIVE_STATES = ["queued", "running", "reviewing", "integrating"] as const;
const ALL_STATES = ["queued", "running", "reviewing", "integrating", "succeeded", "pushed", "no_changes", "blocked", "failed", "cancelled"] as const;
const ACTIVE_FILTER = "status IN ('queued','running','reviewing','integrating')";
const ACTIVE_RANK = "CASE status WHEN 'running' THEN 0 WHEN 'reviewing' THEN 1 WHEN 'integrating' THEN 2 ELSE 3 END";
const HISTORY_FILTER = "status NOT IN ('queued','running','reviewing','integrating')";

function rowToTask(row: Record<string, unknown>): TaskRow {
  return { taskId: String(row.task_id), status: String(row.status), title: String(row.title), summary: String(row.summary), currentPipelineId: row.current_pipeline_id == null ? null : String(row.current_pipeline_id), createdAt: String(row.created_at), updatedAt: String(row.updated_at), archiveState: String(row.archive_state), lastImportAt: row.last_import_at == null ? null : String(row.last_import_at) };
}

function encodeCursor(value: Record<string, unknown>) { return Buffer.from(JSON.stringify(value), "utf8").toString("base64url"); }
function invalidCursor(message = "invalid cursor") { const error = new Error(message) as CursorError; error.code = "INVALID_CURSOR"; return error; }
function staleCursor(message = "cursor is stale") { const error = new Error(message) as CursorError; error.code = "STALE_CURSOR"; return error; }
function decodeCursor(value: string) { try { const decoded = JSON.parse(Buffer.from(value, "base64url").toString("utf8")); if (!isRecord(decoded)) throw new Error(); return decoded; } catch { throw invalidCursor(); } }
function nullableNumber(value: unknown) { return value === null || value === undefined ? null : Number(value); }
function activeRank(status: string) { return status === "running" ? 0 : status === "reviewing" ? 1 : status === "integrating" ? 2 : 3; }
function yieldToEventLoop() { return new Promise<void>((resolve) => setImmediate(resolve)); }

async function hashHandlePrefix(handle: FileHandle, end: number) {
  const digest = createHash("sha256");
  const buffer = Buffer.allocUnsafe(64 * 1024);
  for (let position = 0; position < end;) {
    const length = Math.min(buffer.length, end - position);
    const { bytesRead } = await handle.read(buffer, 0, length, position);
    if (bytesRead !== length) throw staleCursor("accepted archive evidence changed");
    digest.update(buffer.subarray(0, bytesRead));
    position += bytesRead;
    await yieldToEventLoop();
  }
  return digest.digest("hex");
}

async function readHandleRange(handle: FileHandle, start: number, end: number) {
  const length = end - start;
  const buffer = Buffer.allocUnsafe(length);
  let offset = 0;
  while (offset < length) {
    const result = await handle.read(buffer, offset, length - offset, start + offset);
    if (!result.bytesRead) throw staleCursor("accepted archive evidence changed");
    offset += result.bytesRead;
  }
  return buffer;
}

const KNOWN_TRANSCRIPT_TYPES = new Set(["assistant.message", "user.message", "tool.call", "tool.result", "file.change", "synthetic.assistant", "synthetic.tool"]);
function boundedString(value: unknown, limit: number) { return typeof value === "string" ? value.slice(0, limit) : undefined; }
function renderTranscriptValue(source: string, indexedType: unknown) {
  let value: JsonRecord;
  try { value = JSON.parse(source) as JsonRecord; } catch { return { opaque: true, category: "unrecognized-record" }; }
  if (!isRecord(value)) return { opaque: true, category: "unrecognized-record" };
  const type = typeof indexedType === "string" ? indexedType : typeof value.record_type === "string" ? value.record_type : typeof value.type === "string" ? value.type : null;
  if (!type || !KNOWN_TRANSCRIPT_TYPES.has(type)) return { opaque: true, category: "unrecognized-record" };
  const text = boundedString(value.text, 8_192) ?? boundedString(value.message, 8_192);
  const command = boundedString(value.command, 2_048);
  const output = boundedString(value.output, 8_192);
  const exitCode = Number.isSafeInteger(value.exit_code) ? Number(value.exit_code) : undefined;
  return Object.fromEntries(Object.entries({ record_type: type, text, command, output, exit_code: exitCode }).filter(([, item]) => item !== undefined));
}

export class StewardArchiveRepository {
  readonly importer: StewardArchiveImporter;
  readonly config: ArchiveConfig;
  readonly db: DatabaseSync;

  constructor(importer = getArchiveImporter()) { this.importer = importer; this.config = importer.config; this.db = importer.db; }

  getImportStatus(): ImportStatus { return this.importer.status(); }
  getRevision() { return this.importer.revision(); }

  getTaskDashboard(): TaskDashboard {
    const status = this.getImportStatus();
    const counts = Object.fromEntries(ALL_STATES.map((state) => [state, 0])) as Record<string, number> & { total: number; indexed: number; verified: number };
    counts.total = status.taskCount; counts.indexed = status.taskCount; counts.verified = status.verifiedTaskCount;
    for (const row of this.db.prepare("SELECT status, count(*) AS count FROM tasks GROUP BY status").all()) counts[String(row.status)] = Number(row.count);
    const active = this.db.prepare(`SELECT * FROM tasks WHERE ${ACTIVE_FILTER} ORDER BY ${ACTIVE_RANK}, updated_at DESC, task_id DESC LIMIT 50`).all().map(rowToTask);
    const recent = this.db.prepare(`SELECT * FROM tasks WHERE ${HISTORY_FILTER} ORDER BY updated_at DESC, task_id DESC LIMIT 50`).all().map(rowToTask);
    const usage = this.db.prepare("SELECT count(*) AS total_runs, sum(CASE WHEN availability IN ('available','partial') AND total_tokens IS NOT NULL THEN 1 ELSE 0 END) AS token_runs, sum(CASE WHEN prompt_tokens IS NOT NULL THEN 1 ELSE 0 END) AS prompt_runs, sum(CASE WHEN completion_tokens IS NOT NULL THEN 1 ELSE 0 END) AS completion_runs, sum(CASE WHEN total_tokens IS NOT NULL THEN 1 ELSE 0 END) AS total_token_runs, sum(prompt_tokens) AS prompt, sum(completion_tokens) AS completion, sum(total_tokens) AS total, sum(CASE WHEN cost_availability IN ('available','partial') AND estimated_micro_usd IS NOT NULL THEN 1 ELSE 0 END) AS cost_runs, sum(estimated_micro_usd) AS cost FROM usage_facts").get() ?? {};
    return {
      state: status.state, epochId: status.epochId, counts, active, recent,
      usage: { tokens: { prompt: nullableNumber(usage.prompt), completion: nullableNumber(usage.completion), total: nullableNumber(usage.total), availableRuns: Number(usage.token_runs ?? 0), totalRuns: Number(usage.total_runs ?? 0), promptAvailableRuns: Number(usage.prompt_runs ?? 0), completionAvailableRuns: Number(usage.completion_runs ?? 0), totalAvailableRuns: Number(usage.total_token_runs ?? 0) }, cost: { microUsd: nullableNumber(usage.cost), availableRuns: Number(usage.cost_runs ?? 0), totalRuns: Number(usage.total_runs ?? 0) } },
      freshness: { lastAttemptAt: status.lastAttemptAt, lastSuccessAt: status.lastSuccessAt, lagSeconds: status.lagSeconds, errors: status.errorCount },
    };
  }

  listTasksPage(cursor?: string | null, limit = 50): TaskPage {
    const bounded = Math.min(50, Math.max(1, limit));
    const decoded = cursor ? decodeCursor(cursor) : null;
    let rows: Array<Record<string, unknown>>;
    if (!decoded) rows = this.db.prepare(`SELECT * FROM tasks WHERE ${HISTORY_FILTER} ORDER BY updated_at DESC, task_id DESC LIMIT ?`).all(bounded);
    else {
      if (typeof decoded.updatedAt !== "string" || typeof decoded.taskId !== "string" || !isSafeId(decoded.taskId) || !["next", "previous"].includes(String(decoded.direction))) throw invalidCursor();
      if (decoded.direction === "next") rows = this.db.prepare(`SELECT * FROM tasks WHERE ${HISTORY_FILTER} AND (updated_at < ? OR (updated_at = ? AND task_id < ?)) ORDER BY updated_at DESC, task_id DESC LIMIT ?`).all(decoded.updatedAt, decoded.updatedAt, decoded.taskId, bounded);
      else rows = this.db.prepare(`SELECT * FROM tasks WHERE ${HISTORY_FILTER} AND (updated_at > ? OR (updated_at = ? AND task_id > ?)) ORDER BY updated_at ASC, task_id ASC LIMIT ?`).all(decoded.updatedAt, decoded.updatedAt, decoded.taskId, bounded).reverse();
    }
    const tasks = rows.map(rowToTask);
    const first = tasks[0]; const last = tasks.at(-1);
    const hasNewer = first ? Boolean(this.db.prepare(`SELECT 1 FROM tasks WHERE ${HISTORY_FILTER} AND (updated_at > ? OR (updated_at = ? AND task_id > ?)) LIMIT 1`).get(first.updatedAt, first.updatedAt, first.taskId)) : false;
    const hasOlder = last ? Boolean(this.db.prepare(`SELECT 1 FROM tasks WHERE ${HISTORY_FILTER} AND (updated_at < ? OR (updated_at = ? AND task_id < ?)) LIMIT 1`).get(last.updatedAt, last.updatedAt, last.taskId)) : false;
    return { tasks, nextCursor: hasOlder && last ? encodeCursor({ direction: "next", updatedAt: last.updatedAt, taskId: last.taskId }) : null, previousCursor: hasNewer && first ? encodeCursor({ direction: "previous", updatedAt: first.updatedAt, taskId: first.taskId }) : null, total: Number(this.db.prepare(`SELECT count(*) AS count FROM tasks WHERE ${HISTORY_FILTER}`).get()?.count ?? 0), revision: this.getRevision().revision };
  }

  listActiveTasksPage(cursor?: string | null, limit = 50): TaskPage {
    const bounded = Math.min(50, Math.max(1, limit));
    const decoded = cursor ? decodeCursor(cursor) : null;
    let rows: Array<Record<string, unknown>>;
    if (!decoded) rows = this.db.prepare(`SELECT * FROM tasks WHERE ${ACTIVE_FILTER} ORDER BY ${ACTIVE_RANK}, updated_at DESC, task_id DESC LIMIT ?`).all(bounded);
    else {
      if (decoded.scope !== "active" || !Number.isSafeInteger(decoded.rank) || Number(decoded.rank) < 0 || Number(decoded.rank) > 3 || typeof decoded.updatedAt !== "string" || typeof decoded.taskId !== "string" || !isSafeId(decoded.taskId) || !["next", "previous"].includes(String(decoded.direction))) throw invalidCursor();
      if (decoded.direction === "next") rows = this.db.prepare(`SELECT * FROM tasks WHERE ${ACTIVE_FILTER} AND (${ACTIVE_RANK} > ? OR (${ACTIVE_RANK} = ? AND (updated_at < ? OR (updated_at = ? AND task_id < ?)))) ORDER BY ${ACTIVE_RANK}, updated_at DESC, task_id DESC LIMIT ?`).all(decoded.rank, decoded.rank, decoded.updatedAt, decoded.updatedAt, decoded.taskId, bounded);
      else rows = this.db.prepare(`SELECT * FROM tasks WHERE ${ACTIVE_FILTER} AND (${ACTIVE_RANK} < ? OR (${ACTIVE_RANK} = ? AND (updated_at > ? OR (updated_at = ? AND task_id > ?)))) ORDER BY ${ACTIVE_RANK} DESC, updated_at ASC, task_id ASC LIMIT ?`).all(decoded.rank, decoded.rank, decoded.updatedAt, decoded.updatedAt, decoded.taskId, bounded).reverse();
    }
    const tasks = rows.map(rowToTask);
    const first = tasks[0]; const last = tasks.at(-1);
    const firstRank = first ? activeRank(first.status) : 0;
    const lastRank = last ? activeRank(last.status) : 0;
    const hasNewer = first ? Boolean(this.db.prepare(`SELECT 1 FROM tasks WHERE ${ACTIVE_FILTER} AND (${ACTIVE_RANK} < ? OR (${ACTIVE_RANK} = ? AND (updated_at > ? OR (updated_at = ? AND task_id > ?)))) LIMIT 1`).get(firstRank, firstRank, first.updatedAt, first.updatedAt, first.taskId)) : false;
    const hasOlder = last ? Boolean(this.db.prepare(`SELECT 1 FROM tasks WHERE ${ACTIVE_FILTER} AND (${ACTIVE_RANK} > ? OR (${ACTIVE_RANK} = ? AND (updated_at < ? OR (updated_at = ? AND task_id < ?)))) LIMIT 1`).get(lastRank, lastRank, last.updatedAt, last.updatedAt, last.taskId)) : false;
    return {
      tasks,
      nextCursor: hasOlder && last ? encodeCursor({ scope: "active", direction: "next", rank: lastRank, updatedAt: last.updatedAt, taskId: last.taskId }) : null,
      previousCursor: hasNewer && first ? encodeCursor({ scope: "active", direction: "previous", rank: firstRank, updatedAt: first.updatedAt, taskId: first.taskId }) : null,
      total: Number(this.db.prepare(`SELECT count(*) AS count FROM tasks WHERE ${ACTIVE_FILTER}`).get()?.count ?? 0),
      revision: this.getRevision().revision,
    };
  }

  private async acceptedFile(taskId: string, relativePath: string, kind?: string) {
    if (!isSafeId(taskId) || !isSafeRelativePath(relativePath)) throw new Error("invalid archive locator");
    const file = this.db.prepare(`SELECT * FROM files WHERE task_id=? AND relative_path=?${kind ? " AND kind=?" : ""}`).get(...(kind ? [taskId, relativePath, kind] : [taskId, relativePath]));
    if (!file || file.status !== "ready") throw new Error("archive file is unavailable");
    const task = this.db.prepare("SELECT root_relative_path FROM tasks WHERE task_id=?").get(taskId);
    if (!task) throw new Error("task is unavailable");
    const taskRoot = await resolveDirectoryContainedPath(this.config.tasksRoot, String(task.root_relative_path));
    const resolved = await resolveRegularContainedPath(taskRoot, relativePath);
    const acceptedEnd = Number(file.accepted_end);
    if (!Number.isSafeInteger(acceptedEnd) || acceptedEnd < 0) throw staleCursor("accepted archive evidence changed");
    const handle = await open(resolved.path, constants.O_RDONLY | constants.O_NOFOLLOW);
    try {
      const stat = await handle.stat();
      if (!stat.isFile() || stat.dev !== resolved.stat.dev || stat.ino !== resolved.stat.ino || stat.size < acceptedEnd || await hashHandlePrefix(handle, acceptedEnd) !== file.prefix_hash) throw staleCursor("accepted archive evidence changed");
      return { file, handle, acceptedEnd, stat };
    } catch (error) { await handle.close(); throw error; }
  }

  private async acceptedJson(taskId: string, relativePath: string, validator: (value: JsonRecord) => JsonRecord) {
    const accepted = await this.acceptedFile(taskId, relativePath);
    try {
      if (accepted.acceptedEnd > 8 * 1024 * 1024) throw new Error("archive metadata exceeds the supported boundary");
      return validator(parseCompleteJson((await readHandleRange(accepted.handle, 0, accepted.acceptedEnd)).toString("utf8"), relativePath));
    } finally { await accepted.handle.close(); }
  }

  async loadTaskDetail(taskId: string, selection: { pipelineId?: string; runId?: string } = {}) {
    if (!isSafeId(taskId)) return null;
    const taskRow = this.db.prepare("SELECT * FROM tasks WHERE task_id=?").get(taskId);
    if (!taskRow) return null;
    const task = await this.acceptedJson(taskId, "task.json", validateTask);
    const pipelineRows = this.db.prepare("SELECT * FROM pipelines WHERE task_id=? ORDER BY ordinal").all(taskId);
    const pipelineDetails = [];
    for (const pipelineRow of pipelineRows) {
      if (selection.pipelineId && selection.pipelineId !== String(pipelineRow.pipeline_id)) continue;
      const pipeline = await this.acceptedJson(taskId, String(pipelineRow.metadata_path), validatePipeline);
      const runs = [];
      for (const runRow of this.db.prepare("SELECT * FROM runs WHERE task_id=? AND pipeline_id=? ORDER BY role_ordinal, run_id").all(taskId, pipeline.pipelineId)) {
        if (selection.runId && selection.runId !== String(runRow.run_id)) continue;
        const run = await this.acceptedJson(taskId, String(runRow.metadata_path), validateRun);
        const usage = this.db.prepare("SELECT * FROM usage_facts WHERE task_id=? AND run_id=?").get(taskId, run.runId);
        const files = this.db.prepare("SELECT relative_path, kind, media_type, lifecycle, actual_size, accepted_end, prefix_hash, prefix_revision, complete_records, file_revision, status FROM files WHERE task_id=? AND relative_path LIKE ? ORDER BY relative_path").all(taskId, `pipelines/${pipeline.pipelineId}/runs/${run.runId}/%`);
        runs.push({ ...run, indexedUsage: usage ?? null, indexedFiles: files });
      }
      const validations = [];
      for (const ref of pipeline.validations as JsonRecord[]) validations.push(await this.acceptedJson(taskId, String(ref.path), validateValidation));
      const reviews = [];
      for (const ref of pipeline.reviews as JsonRecord[]) reviews.push(await this.acceptedJson(taskId, String(ref.path), validateReview));
      pipelineDetails.push({ pipeline, validations, reviews, runs });
    }
    return { schemaVersion: "2.0", generatedAt: new Date().toISOString(), data: { task, pipelines: pipelineDetails, archiveState: taskRow.archive_state, archiveVerification: { state: taskRow.archive_state, manifestObservedAt: taskRow.manifest_observed_at ?? null, verifiedAt: taskRow.verified_at ?? null, reason: taskRow.archive_reason ?? null }, freshness: { lastSyncAt: taskRow.last_import_at ?? null, lastSuccessfulImportAt: taskRow.last_import_at ?? null }, importLag: taskRow.archive_reason ? { category: "archive", reason: String(taskRow.archive_reason) } : null } };
  }

  async readTranscriptChunk(taskId: string, runId: string, relativePath: string, cursor?: string | null, limit = 50) {
    if (!isSafeId(taskId) || !isSafeId(runId) || !isSafeRelativePath(relativePath)) throw new Error("invalid transcript locator");
    const run = this.db.prepare("SELECT pipeline_id FROM runs WHERE task_id=? AND run_id=?").get(taskId, runId);
    if (!run || !relativePath.startsWith(`pipelines/${String(run.pipeline_id)}/runs/${runId}/`)) throw new Error("transcript is not owned by the selected run");
    const accepted = await this.acceptedFile(taskId, relativePath, "jsonl");
    try {
      const fileRevision = String(accepted.file.file_revision ?? "");
      const cursorData = cursor ? decodeCursor(cursor) : null;
      if (cursorData && (cursorData.taskId !== taskId || cursorData.runId !== runId || cursorData.relativePath !== relativePath || cursorData.fileRevision !== fileRevision)) throw staleCursor();
      const startOrdinal = cursorData ? Number(cursorData.ordinal) : 0;
      if (!Number.isSafeInteger(startOrdinal) || startOrdinal < 0) throw invalidCursor();
      if (cursorData) {
        const prefixEnd = Number(cursorData.prefixEnd);
        if (!Number.isSafeInteger(prefixEnd) || prefixEnd < 0 || typeof cursorData.prefixHash !== "string") throw invalidCursor();
        const preceding = startOrdinal === 0 ? null : this.db.prepare("SELECT byte_end FROM records WHERE task_id=? AND relative_path=? AND ordinal=?").get(taskId, relativePath, startOrdinal - 1);
        if ((startOrdinal === 0 && prefixEnd !== 0) || (startOrdinal > 0 && Number(preceding?.byte_end) !== prefixEnd) || await hashHandlePrefix(accepted.handle, prefixEnd) !== cursorData.prefixHash) throw staleCursor();
      }
      const bounded = Math.min(100, Math.max(1, Number.isFinite(limit) ? Math.floor(limit) : 50));
      const rows = this.db.prepare("SELECT ordinal, byte_start, byte_end, timestamp, record_type FROM records WHERE task_id=? AND relative_path=? AND ordinal>=? ORDER BY ordinal LIMIT ?").all(taskId, relativePath, startOrdinal, bounded + 1);
      const pageRows = rows.slice(0, bounded);
      const rangeStart = Number(pageRows[0]?.byte_start ?? 0);
      const rangeEnd = Number(pageRows.at(-1)?.byte_end ?? rangeStart);
      const bytes = rangeEnd > rangeStart ? await readHandleRange(accepted.handle, rangeStart, rangeEnd) : Buffer.alloc(0);
      const records = pageRows.map((row) => {
        const start = Number(row.byte_start); const end = Number(row.byte_end);
        if (start < rangeStart || end <= start || end > rangeEnd || bytes[end - rangeStart - 1] !== 10) throw staleCursor("indexed transcript boundary changed");
        const line = bytes.subarray(start - rangeStart, end - rangeStart - 1).toString("utf8");
        const value = renderTranscriptValue(line, row.record_type);
        return { ordinal: Number(row.ordinal), timestamp: row.timestamp ?? null, type: value.opaque === true ? "opaque" : row.record_type ?? "opaque", value };
      });
      const hasMore = rows.length > bounded;
      const nextOrdinal = pageRows.length ? Number(pageRows.at(-1)?.ordinal) + 1 : startOrdinal;
      const prefixEnd = pageRows.length ? Number(pageRows.at(-1)?.byte_end) : cursorData ? Number(cursorData.prefixEnd) : 0;
      const prefixHash = await hashHandlePrefix(accepted.handle, prefixEnd);
      const nextCursor = encodeCursor({ taskId, runId, relativePath, fileRevision, ordinal: nextOrdinal, prefixEnd, prefixHash });
      return { schemaVersion: "2.0", generatedAt: new Date().toISOString(), data: { taskId, pipelineId: run.pipeline_id, runId, file: { path: relativePath, fileRevision, acceptedEnd: Number(accepted.file.accepted_end), completeRecords: Number(accepted.file.complete_records) }, records, nextCursor, previousCursor: startOrdinal > 0 ? encodeCursor({ taskId, runId, relativePath, fileRevision, ordinal: 0, prefixEnd: 0, prefixHash: await hashHandlePrefix(accepted.handle, 0) }) : null, hasMore } };
    } finally { await accepted.handle.close(); }
  }

  async readArtifact(taskId: string, relativePath: string) {
    const accepted = await this.acceptedFile(taskId, relativePath);
    const declaredType = String(accepted.file.media_type ?? "application/octet-stream");
    const contentType = ["application/json", "application/x-ndjson", "text/plain", "text/markdown", "text/x-diff", "application/octet-stream"].includes(declaredType) ? declaredType : "application/octet-stream";
    const stream = accepted.acceptedEnd === 0 ? Readable.from([]) : accepted.handle.createReadStream({ start: 0, end: accepted.acceptedEnd - 1, autoClose: true });
    if (accepted.acceptedEnd === 0) await accepted.handle.close();
    return { stream, contentType, filename: basename(relativePath), size: accepted.acceptedEnd, active: accepted.file.lifecycle !== "terminal" || accepted.file.status !== "ready" };
  }
}

let repository: StewardArchiveRepository | null = null;
export function getArchiveRepository(config?: ArchiveConfig) { if (!repository) repository = new StewardArchiveRepository(getArchiveImporter(config)); repository.importer.start(); return repository; }
export function resetArchiveRepository() { repository = null; }
export { encodeCursor, decodeCursor, ACTIVE_STATES, ALL_STATES };

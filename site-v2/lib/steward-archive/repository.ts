import { readFile } from "node:fs/promises";
import { basename } from "node:path";
import type { DatabaseSync } from "node:sqlite";
import { getArchiveConfig, type ArchiveConfig } from "./config";
import { getArchiveImporter, type ImportStatus, type StewardArchiveImporter } from "./importer";
import { isSafeId, isSafeRelativePath, resolveRegularContainedPath, resolveSafePath } from "./paths";
import { isRecord, parseCompleteJson, safeString, validatePipeline, validateRun, validateTask, validateValidation, validateReview } from "./schema";

export type CursorError = Error & { code?: "STALE_CURSOR" | "INVALID_CURSOR" };

export interface TaskRow {
  taskId: string;
  status: string;
  title: string;
  summary: string;
  currentPipelineId: string | null;
  createdAt: string;
  updatedAt: string;
  archiveState: string;
  lastImportAt: string | null;
}

export interface UsageAggregate {
  tokens: { prompt: number; completion: number; total: number; availableRuns: number; totalRuns: number; promptAvailableRuns: number; completionAvailableRuns: number; totalAvailableRuns: number };
  cost: { microUsd: number; availableRuns: number; totalRuns: number };
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

function rowToTask(row: Record<string, unknown>): TaskRow {
  return { taskId: String(row.task_id), status: String(row.status), title: String(row.title), summary: String(row.summary), currentPipelineId: row.current_pipeline_id == null ? null : String(row.current_pipeline_id), createdAt: String(row.created_at), updatedAt: String(row.updated_at), archiveState: String(row.archive_state), lastImportAt: row.last_import_at == null ? null : String(row.last_import_at) };
}

function encodeCursor(value: Record<string, unknown>) { return Buffer.from(JSON.stringify(value), "utf8").toString("base64url"); }
function decodeCursor(value: string) { try { const decoded = JSON.parse(Buffer.from(value, "base64url").toString("utf8")); if (!isRecord(decoded)) throw new Error(); return decoded; } catch { const error = new Error("invalid cursor") as CursorError; error.code = "INVALID_CURSOR"; throw error; } }

function firstNonEmpty<T>(...values: Array<T | null | undefined>) { return values.find((value) => value !== null && value !== undefined) as T | undefined; }

export class StewardArchiveRepository {
  readonly importer: StewardArchiveImporter;
  readonly config: ArchiveConfig;
  readonly db: DatabaseSync;

  constructor(importer = getArchiveImporter()) { this.importer = importer; this.config = importer.config; this.db = importer.db; }

  getImportStatus(): ImportStatus { return this.importer.status(); }
  getRevision() { return this.importer.revision(); }

  getTaskDashboard(): TaskDashboard {
    const status = this.getImportStatus();
    const rows = this.db.prepare("SELECT status, count(*) AS count FROM tasks GROUP BY status").all();
    const counts: Record<string, number> & { total: number; indexed: number; verified: number } = { total: status.taskCount, indexed: status.taskCount, verified: status.verifiedTaskCount };
    for (const row of rows) counts[String(row.status)] = Number(row.count);
    const active = this.db.prepare("SELECT * FROM tasks WHERE status IN ('queued','running','reviewing','integrating') ORDER BY CASE status WHEN 'running' THEN 0 WHEN 'reviewing' THEN 1 WHEN 'integrating' THEN 2 ELSE 3 END, updated_at DESC, task_id LIMIT 50").all().map(rowToTask);
    const recent = this.db.prepare("SELECT * FROM tasks WHERE status NOT IN ('queued','running','reviewing','integrating') ORDER BY updated_at DESC, task_id LIMIT 50").all().map(rowToTask);
    const usageRows = this.db.prepare("SELECT count(*) AS total_runs, sum(CASE WHEN availability IN ('available','partial') AND total_tokens IS NOT NULL THEN 1 ELSE 0 END) AS token_runs, sum(CASE WHEN prompt_tokens IS NOT NULL THEN 1 ELSE 0 END) AS prompt_runs, sum(CASE WHEN completion_tokens IS NOT NULL THEN 1 ELSE 0 END) AS completion_runs, sum(CASE WHEN total_tokens IS NOT NULL THEN 1 ELSE 0 END) AS total_token_runs, sum(CASE WHEN prompt_tokens IS NOT NULL THEN prompt_tokens ELSE 0 END) AS prompt, sum(CASE WHEN completion_tokens IS NOT NULL THEN completion_tokens ELSE 0 END) AS completion, sum(CASE WHEN total_tokens IS NOT NULL THEN total_tokens ELSE 0 END) AS total, sum(CASE WHEN cost_availability IN ('available','partial') AND estimated_micro_usd IS NOT NULL THEN 1 ELSE 0 END) AS cost_runs, sum(CASE WHEN estimated_micro_usd IS NOT NULL THEN estimated_micro_usd ELSE 0 END) AS cost FROM usage_facts").get() ?? {};
    return {
      state: status.state, epochId: status.epochId, counts, active, recent,
      usage: { tokens: { prompt: Number(usageRows.prompt ?? 0), completion: Number(usageRows.completion ?? 0), total: Number(usageRows.total ?? 0), availableRuns: Number(usageRows.token_runs ?? 0), totalRuns: Number(usageRows.total_runs ?? 0), promptAvailableRuns: Number(usageRows.prompt_runs ?? 0), completionAvailableRuns: Number(usageRows.completion_runs ?? 0), totalAvailableRuns: Number(usageRows.total_token_runs ?? 0) }, cost: { microUsd: Number(usageRows.cost ?? 0), availableRuns: Number(usageRows.cost_runs ?? 0), totalRuns: Number(usageRows.total_runs ?? 0) } },
      freshness: { lastAttemptAt: status.lastAttemptAt, lastSuccessAt: status.lastSuccessAt, lagSeconds: status.lagSeconds, errors: status.errorCount },
    };
  }

  listTasksPage(cursor?: string | null, limit = 50): TaskPage {
    const bounded = Math.min(50, Math.max(1, limit));
    const revision = this.getRevision().revision;
    let rows: Array<Record<string, unknown>>;
    const decoded = cursor ? decodeCursor(cursor) : null;
    if (decoded) {
      if (decoded.revision !== revision) { const error = new Error("cursor is stale") as CursorError; error.code = "STALE_CURSOR"; throw error; }
      if (typeof decoded.updatedAt !== "string" || typeof decoded.taskId !== "string") { const error = new Error("invalid cursor") as CursorError; error.code = "INVALID_CURSOR"; throw error; }
      rows = this.db.prepare("SELECT * FROM tasks WHERE (updated_at < ? OR (updated_at = ? AND task_id < ?)) ORDER BY updated_at DESC, task_id DESC LIMIT ?").all(decoded.updatedAt, decoded.updatedAt, decoded.taskId, bounded + 1);
    } else rows = this.db.prepare("SELECT * FROM tasks ORDER BY updated_at DESC, task_id DESC LIMIT ?").all(bounded + 1);
    const hasNext = rows.length > bounded;
    const tasks = rows.slice(0, bounded).map(rowToTask);
    const nextCursor = hasNext && tasks.length ? encodeCursor({ revision, updatedAt: tasks.at(-1)!.updatedAt, taskId: tasks.at(-1)!.taskId }) : null;
    return { tasks, nextCursor, previousCursor: null, total: Number(this.db.prepare("SELECT count(*) AS count FROM tasks").get()?.count ?? 0), revision };
  }

  async loadTaskDetail(taskId: string, selection: { pipelineId?: string; runId?: string; artifactPath?: string } = {}) {
    if (!isSafeId(taskId)) return null;
    const taskRow = this.db.prepare("SELECT * FROM tasks WHERE task_id=?").get(taskId);
    if (!taskRow) return null;
    const taskRoot = resolveSafePath(this.config.tasksRoot, String(taskRow.root_relative_path));
    const task = validateTask(parseCompleteJson(await readFile(resolveSafePath(taskRoot, "task.json"), "utf8"), "task.json"));
    const pipelineRows = this.db.prepare("SELECT * FROM pipelines WHERE task_id=? ORDER BY ordinal").all(taskId);
    const pipelineDetails = [];
    for (const pipelineRow of pipelineRows) {
      if (selection.pipelineId && selection.pipelineId !== String(pipelineRow.pipeline_id)) continue;
      const pipelinePath = resolveSafePath(taskRoot, String(pipelineRow.metadata_path));
      const pipeline = validatePipeline(parseCompleteJson(await readFile(pipelinePath, "utf8"), "pipeline.json"));
      const runs = [];
      for (const runRow of this.db.prepare("SELECT * FROM runs WHERE task_id=? AND pipeline_id=? ORDER BY role_ordinal").all(taskId, pipeline.pipelineId)) {
        if (selection.runId && selection.runId !== String(runRow.run_id)) continue;
        const run = validateRun(parseCompleteJson(await readFile(resolveSafePath(taskRoot, String(runRow.metadata_path)), "utf8"), "run.json"));
        const usage = this.db.prepare("SELECT * FROM usage_facts WHERE task_id=? AND run_id=?").get(taskId, run.runId);
        const files = this.db.prepare("SELECT relative_path, kind, media_type, lifecycle, actual_size, accepted_end, prefix_hash, complete_records, file_revision, status FROM files WHERE task_id=? AND relative_path LIKE ? ORDER BY relative_path").all(taskId, `pipelines/${pipeline.pipelineId}/runs/${run.runId}/%`);
        runs.push({ ...run, indexedUsage: usage ?? null, indexedFiles: files });
      }
      const validations = [];
      for (const ref of (pipeline.validations as unknown[])) { if (!isRecord(ref) || typeof ref.path !== "string") continue; try { validations.push(validateValidation(parseCompleteJson(await readFile(resolveSafePath(taskRoot, ref.path), "utf8"), "validation.json"))); } catch { /* live metadata may be incomplete */ } }
      const reviews = [];
      for (const ref of (pipeline.reviews as unknown[])) { if (!isRecord(ref) || typeof ref.path !== "string") continue; try { reviews.push(validateReview(parseCompleteJson(await readFile(resolveSafePath(taskRoot, ref.path), "utf8"), "review.json"))); } catch { /* live metadata may be incomplete */ } }
      pipelineDetails.push({ pipeline, validations, reviews, runs });
    }
    return { schemaVersion: "2.0", generatedAt: new Date().toISOString(), data: { task, pipelines: pipelineDetails, archiveState: taskRow.archive_state, archiveVerification: { state: taskRow.archive_state, manifestObservedAt: taskRow.manifest_observed_at ?? null, verifiedAt: taskRow.verified_at ?? null, reason: taskRow.archive_reason ?? null }, freshness: { lastSyncAt: taskRow.last_import_at ?? null, lastSuccessfulImportAt: taskRow.last_import_at ?? null }, importLag: taskRow.archive_reason ? { category: "archive", reason: String(taskRow.archive_reason) } : null } };
  }

  async readTranscriptChunk(taskId: string, runId: string, relativePath: string, cursor?: string | null, limit = 50) {
    if (!isSafeId(taskId) || !isSafeId(runId) || !isSafeRelativePath(relativePath)) throw new Error("invalid transcript locator");
    const runLocator = this.db.prepare("SELECT pipeline_id FROM runs WHERE task_id=? AND run_id=?").get(taskId, runId);
    if (!runLocator || !relativePath.startsWith(`pipelines/${String(runLocator.pipeline_id)}/runs/${runId}/`)) throw new Error("transcript is not owned by the selected run");
    const file = this.db.prepare("SELECT * FROM files WHERE task_id=? AND relative_path=? AND kind='jsonl'").get(taskId, relativePath);
    if (!file) throw new Error("transcript is unavailable");
    const cursorData = cursor ? decodeCursor(cursor) : null;
    const revision = String(file.file_revision ?? "");
    if (cursorData && (cursorData.taskId !== taskId || cursorData.runId !== runId || cursorData.relativePath !== relativePath || cursorData.fileRevision !== revision)) { const error = new Error("cursor is stale") as CursorError; error.code = "STALE_CURSOR"; throw error; }
    const startOrdinal = cursorData ? Number(cursorData.ordinal) : 0;
    if (!Number.isSafeInteger(startOrdinal) || startOrdinal < 0) { const error = new Error("invalid cursor") as CursorError; error.code = "INVALID_CURSOR"; throw error; }
    const rows = this.db.prepare("SELECT ordinal, byte_start, byte_end, timestamp, record_type FROM records WHERE task_id=? AND relative_path=? AND ordinal>=? ORDER BY ordinal LIMIT ?").all(taskId, relativePath, startOrdinal, Math.min(100, Math.max(1, limit)));
    const taskRootRow = this.db.prepare("SELECT root_relative_path FROM tasks WHERE task_id=?").get(taskId);
    if (!taskRootRow) throw new Error("task is unavailable");
    const { path } = await resolveRegularContainedPath(resolveSafePath(this.config.tasksRoot, String(taskRootRow.root_relative_path)), relativePath);
    const bytes = await readFile(path);
    const acceptedEnd = Number(file.accepted_end);
    const records = [];
    for (const row of rows) {
      const start = Number(row.byte_start); const end = Math.min(Number(row.byte_end), acceptedEnd);
      if (end > acceptedEnd || end <= start) continue;
      const line = bytes.subarray(start, end).toString("utf8").trimEnd();
      try { records.push({ ordinal: Number(row.ordinal), timestamp: row.timestamp ?? null, type: row.record_type ?? null, value: JSON.parse(line) }); } catch { /* opaque malformed complete record */ }
    }
    const nextOrdinal = rows.length === Math.min(100, Math.max(1, limit)) ? Number(rows.at(-1)?.ordinal ?? startOrdinal) + 1 : null;
    return { schemaVersion: "2.0", generatedAt: new Date().toISOString(), data: { taskId, pipelineId: this.db.prepare("SELECT pipeline_id FROM runs WHERE task_id=? AND run_id=?").get(taskId, runId)?.pipeline_id ?? null, runId, file: { path: relativePath, fileRevision: revision, acceptedEnd, completeRecords: Number(file.complete_records) }, records, nextCursor: nextOrdinal === null ? null : encodeCursor({ taskId, runId, relativePath, fileRevision: revision, ordinal: nextOrdinal }), previousCursor: startOrdinal > 0 ? encodeCursor({ taskId, runId, relativePath, fileRevision: revision, ordinal: Math.max(0, startOrdinal - Math.min(100, Math.max(1, limit))) }) : null, hasMore: nextOrdinal !== null } };
  }

  async readArtifact(taskId: string, relativePath: string) {
    if (!isSafeId(taskId) || !isSafeRelativePath(relativePath)) throw new Error("invalid artifact locator");
    const file = this.db.prepare("SELECT * FROM files WHERE task_id=? AND relative_path=?").get(taskId, relativePath);
    if (!file) throw new Error("artifact is unavailable");
    const taskRootRow = this.db.prepare("SELECT root_relative_path FROM tasks WHERE task_id=?").get(taskId);
    if (!taskRootRow) throw new Error("task is unavailable");
    const taskRoot = resolveSafePath(this.config.tasksRoot, String(taskRootRow.root_relative_path));
    const { path, stat } = await resolveRegularContainedPath(taskRoot, relativePath);
    const declaredType = String(file.media_type ?? "application/octet-stream");
    const contentType = ["application/json", "application/x-ndjson", "text/plain", "text/markdown", "text/x-diff", "application/octet-stream"].includes(declaredType) ? declaredType : "application/octet-stream";
    return { bytes: await readFile(path), contentType, filename: basename(relativePath), size: stat.size, active: file.lifecycle !== "terminal" || file.status !== "ready" };
  }
}

let repository: StewardArchiveRepository | null = null;
export function getArchiveRepository(config?: ArchiveConfig) { if (!repository) repository = new StewardArchiveRepository(getArchiveImporter(config)); repository.importer.start(); return repository; }
export function resetArchiveRepository() { repository = null; }

export { encodeCursor, decodeCursor };

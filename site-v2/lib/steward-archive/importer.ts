import { createHash } from "node:crypto";
import { existsSync, lstatSync, readFileSync, renameSync } from "node:fs";
import { readdir, readFile } from "node:fs/promises";
import { watch as fsWatch, type FSWatcher } from "node:fs";
import { dirname, join } from "node:path";
import { openArchiveDatabase, readDatabaseMeta, updateDatabaseMeta, withTransaction, type DatabaseMeta } from "./database";
import { getArchiveConfig, type ArchiveConfig } from "./config";
import { assertDirectoryRoot, isSafeId, isSafeRelativePath, resolveRegularContainedPath, resolveSafePath } from "./paths";
import { isRecord, parseCompleteJson, safeInteger, safeString, validateEpoch, validatePipeline, validateReview, validateRun, validateTask, validateValidation, type JsonRecord } from "./schema";
import type { DatabaseSync } from "node:sqlite";

export type ImportState = "indexing" | "ready" | "degraded" | "unavailable" | "incompatible" | "archive-corrupt";

export interface ImportStatus extends DatabaseMeta {
  state: ImportState;
  taskCount: number;
  verifiedTaskCount: number;
  errorCount: number;
  lagSeconds: number | null;
  watchState: string;
}

type FileDescriptor = {
  path: string;
  lifecycle?: string;
  availability?: string;
  mediaType?: string | null;
  byteSize?: number | null;
  sha256?: string | null;
  requiredAtTerminal?: boolean;
};

const JSONL_NAMES = new Set(["events.jsonl", "codex.jsonl", "activities.jsonl", "manifest.jsonl"]);
const JSON_NAMES = new Set(["task.json", "pipeline.json", "run.json", "validation.json", "integration.json", "telemetry.json", "result.json", "summary.json", "epoch.json"]);
const TERMINAL_STATES = new Set(["succeeded", "pushed", "no_changes", "blocked", "failed", "cancelled"]);

function now() { return new Date().toISOString(); }
function hash(bytes: Buffer | string) { return createHash("sha256").update(bytes).digest("hex"); }
function fileMediaType(path: string) {
  if (path.endsWith(".jsonl")) return "application/x-ndjson";
  if (path.endsWith(".json")) return "application/json";
  if (path.endsWith(".md")) return "text/markdown";
  if (path.endsWith(".diff")) return "text/x-diff";
  if (path.endsWith(".log")) return "text/plain";
  return "application/octet-stream";
}
function fileKind(path: string) { return JSONL_NAMES.has(path.split("/").at(-1) ?? "") ? "jsonl" : "artifact"; }
function relativePath(root: string, path: string) { return path.slice(root.length + 1).split("\\").join("/"); }
function nullable(value: unknown) { return value == null ? null : value; }

function descriptorFrom(value: unknown): FileDescriptor | null {
  if (!isRecord(value) || typeof value.path !== "string" || !isSafeRelativePath(value.path)) return null;
  return { path: value.path, lifecycle: safeString(value.lifecycle) ?? "live", availability: safeString(value.availability) ?? "available", mediaType: safeString(value.mediaType), byteSize: typeof value.byteSize === "number" ? value.byteSize : null, sha256: safeString(value.sha256), requiredAtTerminal: value.requiredAtTerminal === true };
}

function descriptorsFromMetadata(task: JsonRecord, pipelines: JsonRecord[], runs: JsonRecord[], validations: JsonRecord[], reviews: JsonRecord[]) {
  const descriptors: FileDescriptor[] = [];
  const add = (value: unknown) => { const descriptor = descriptorFrom(value); if (descriptor && !descriptors.some((item) => item.path === descriptor.path)) descriptors.push(descriptor); };
  add({ path: task.promptPath, lifecycle: "terminal", availability: "available", mediaType: "text/markdown", requiredAtTerminal: true });
  add({ path: task.eventsPath, lifecycle: "live", availability: "available", mediaType: "application/x-ndjson", requiredAtTerminal: true });
  for (const pipeline of pipelines) {
    for (const key of ["inputs", "patches"]) if (Array.isArray(pipeline[key])) for (const item of pipeline[key]) add(item);
    if (isRecord(pipeline.integration)) add({ path: pipeline.integration.resultPath, lifecycle: "terminal", availability: pipeline.integration.state === "unavailable" ? "unavailable" : "available", mediaType: "application/json", requiredAtTerminal: pipeline.integration.state !== "pending" });
  }
  for (const validation of validations) { add({ path: validation.outputPath, ...((isRecord(validation.output) ? validation.output : {})) }); }
  for (const review of reviews) add(review.artifact);
  for (const run of runs) {
    if (isRecord(run.artifacts)) for (const descriptor of Object.values(run.artifacts)) add(descriptor);
  }
  return descriptors;
}

export class StewardArchiveImporter {
  readonly config: ArchiveConfig;
  readonly db: DatabaseSync;
  private running = false;
  private queued = false;
  private watcher: FSWatcher | null = null;
  private timer: ReturnType<typeof setInterval> | null = null;

  constructor(config = getArchiveConfig()) {
    this.config = config;
    try {
      this.db = openArchiveDatabase(config.cachePath);
    } catch {
      if (existsSync(config.cachePath)) {
        try { renameSync(config.cachePath, `${config.cachePath}.invalid-${Date.now()}`); } catch { /* a read-only cache is rebuilt in place when possible */ }
        for (const suffix of ["-wal", "-shm"]) {
          if (existsSync(`${config.cachePath}${suffix}`)) {
            try { renameSync(`${config.cachePath}${suffix}`, `${config.cachePath}.invalid-${Date.now()}${suffix}`); } catch { /* cache sidecars are disposable */ }
          }
        }
      }
      this.db = openArchiveDatabase(config.cachePath);
    }
  }

  status(): ImportStatus {
    const meta = readDatabaseMeta(this.db);
    const taskCount = Number(this.db.prepare("SELECT count(*) AS count FROM tasks").get()?.count ?? 0);
    const verifiedTaskCount = Number(this.db.prepare("SELECT count(*) AS count FROM tasks WHERE archive_state='verified'").get()?.count ?? 0);
    const errorCount = Number(this.db.prepare("SELECT coalesce(sum(count), 0) AS count FROM importer_errors").get()?.count ?? 0);
    const lagSeconds = meta.lastSuccessAt ? Math.max(0, Math.floor((Date.now() - Date.parse(meta.lastSuccessAt)) / 1000)) : null;
    return { ...meta, state: meta.state as ImportState, taskCount, verifiedTaskCount, errorCount, lagSeconds, watchState: this.watcher ? "watching" : "stopped" };
  }

  revision() { return { revision: readDatabaseMeta(this.db).revision, state: readDatabaseMeta(this.db).state as ImportState }; }

  start() {
    if (this.watcher || this.timer) return;
    try {
      this.watcher = fsWatch(this.config.tasksRoot, { recursive: true }, () => { void this.requestReconcile(); });
      updateDatabaseMeta(this.db, { watchState: "watching" });
    } catch {
      updateDatabaseMeta(this.db, { watchState: "unavailable" });
    }
    this.timer = setInterval(() => { void this.requestReconcile(); }, this.config.reconcileMs);
    this.timer.unref?.();
    void this.requestReconcile();
  }

  stop() {
    this.watcher?.close(); this.watcher = null;
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
  }

  async requestReconcile() {
    if (this.running) { this.queued = true; return; }
    this.running = true;
    try { await this.reconcile(); } finally {
      this.running = false;
      if (this.queued) { this.queued = false; void this.requestReconcile(); }
    }
  }

  async reconcile() {
    const attemptedAt = now();
    updateDatabaseMeta(this.db, { lastAttemptAt: attemptedAt });
    const started = Date.now();
    if (!existsSync(this.config.tasksRoot)) {
      updateDatabaseMeta(this.db, { state: "unavailable", lastErrorCategory: "archive-root-missing", lastErrorCount: 1 });
      return;
    }
    try { await assertDirectoryRoot(this.config.tasksRoot); } catch {
      updateDatabaseMeta(this.db, { state: "unavailable", lastErrorCategory: "archive-root-invalid", lastErrorCount: 1 });
      return;
    }
    let epoch: ReturnType<typeof validateEpoch>;
    try {
      const epochPath = resolveSafePath(this.config.tasksRoot, "epoch.json");
      epoch = validateEpoch(parseCompleteJson(await readFile(epochPath, "utf8"), "epoch.json"));
    } catch {
      const previous = readDatabaseMeta(this.db).epochId;
      updateDatabaseMeta(this.db, { state: previous ? "degraded" : "unavailable", lastErrorCategory: "epoch-unavailable", lastErrorCount: 1 });
      return;
    }
    const previousMeta = readDatabaseMeta(this.db);
    if (previousMeta.epochId && previousMeta.epochId !== epoch.epochId) {
      updateDatabaseMeta(this.db, { state: "incompatible", lastErrorCategory: "epoch-changed", lastErrorCount: 1 });
      return;
    }
    updateDatabaseMeta(this.db, { epochId: epoch.epochId, state: "indexing" });
    let changed = false;
    let failures = 0;
    let archiveCorrupt = false;
    let entries;
    try { entries = await readdir(this.config.tasksRoot, { withFileTypes: true }); } catch { updateDatabaseMeta(this.db, { state: "degraded", lastErrorCategory: "archive-read", lastErrorCount: 1 }); return; }
    for (const entry of entries) {
      if (!entry.isDirectory() || entry.name.startsWith(".") || !isSafeId(entry.name)) continue;
      try {
        const result = await this.importTask(entry.name, epoch.epochId);
        changed ||= result.changed;
        archiveCorrupt ||= result.archiveState === "corrupt";
      } catch (error) {
        failures += 1;
        this.recordError(entry.name, "task-import");
      }
      await new Promise<void>((resolve) => setImmediate(resolve));
    }
    const finalState: ImportState = archiveCorrupt ? "archive-corrupt" : failures ? "degraded" : "ready";
    const meta = readDatabaseMeta(this.db);
    updateDatabaseMeta(this.db, { state: finalState, lastSuccessAt: now(), lastErrorCategory: failures ? "task-import" : null, lastErrorCount: failures, revision: meta.revision + (changed ? 1 : 0), lastScanDurationMs: Date.now() - started });
  }

  private recordError(taskId: string | null, category: string) {
    const timestamp = now();
    this.db.prepare(`INSERT INTO importer_errors(task_id, category, count, first_seen_at, last_seen_at) VALUES(?, ?, 1, ?, ?) ON CONFLICT(task_id, category) DO UPDATE SET count=count+1, last_seen_at=excluded.last_seen_at`).run(taskId, category, timestamp, timestamp);
  }

  private async importTask(directoryName: string, epochId: string) {
    const root = resolveSafePath(this.config.tasksRoot, directoryName);
    const task = validateTask(parseCompleteJson(await readFile(join(root, "task.json"), "utf8"), "task.json"));
    const taskId = String(task.taskId);
    if (task.epochId !== epochId) throw new Error("task identity mismatch");
    const pipelines: JsonRecord[] = [];
    const runs: JsonRecord[] = [];
    const validations: JsonRecord[] = [];
    const reviews: JsonRecord[] = [];
    for (const ref of task.pipelines as unknown[]) {
      if (!isRecord(ref) || typeof ref.path !== "string" || !isSafeRelativePath(ref.path)) throw new Error("invalid pipeline reference");
      const pipeline = validatePipeline(parseCompleteJson(await readFile(resolveSafePath(root, ref.path), "utf8"), "pipeline.json"));
      pipelines.push(pipeline);
      if (Array.isArray(pipeline.runs)) for (const runRef of pipeline.runs) {
        if (!isRecord(runRef) || typeof runRef.path !== "string" || !isSafeRelativePath(runRef.path)) continue;
        try { runs.push(validateRun(parseCompleteJson(await readFile(resolveSafePath(root, runRef.path), "utf8"), "run.json"))); } catch { this.recordError(taskId, "run-metadata"); }
      }
      if (Array.isArray(pipeline.validations)) for (const validationRef of pipeline.validations) {
        if (!isRecord(validationRef) || typeof validationRef.path !== "string" || !isSafeRelativePath(validationRef.path)) continue;
        try { validations.push(validateValidation(parseCompleteJson(await readFile(resolveSafePath(root, validationRef.path), "utf8"), "validation.json"))); } catch { this.recordError(taskId, "validation-metadata"); }
      }
      if (Array.isArray(pipeline.reviews)) for (const reviewRef of pipeline.reviews) {
        if (!isRecord(reviewRef) || typeof reviewRef.path !== "string" || !isSafeRelativePath(reviewRef.path)) continue;
        try { reviews.push(validateReview(parseCompleteJson(await readFile(resolveSafePath(root, reviewRef.path), "utf8"), "review.json"))); } catch { this.recordError(taskId, "review-metadata"); }
      }
    }
    const descriptors = descriptorsFromMetadata(task, pipelines, runs, validations, reviews);
    const importedAt = now();
    const result = withTransaction(this.db, () => {
      const previous = this.db.prepare("SELECT status, title, summary, updated_at, archive_state, last_import_at FROM tasks WHERE task_id=?").get(taskId);
      this.db.prepare(`INSERT INTO tasks(task_id, epoch_id, status, title, summary, prompt_path, events_path, current_pipeline_id, created_at, updated_at, root_relative_path, last_import_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(task_id) DO UPDATE SET epoch_id=excluded.epoch_id, status=excluded.status, title=excluded.title, summary=excluded.summary, prompt_path=excluded.prompt_path, events_path=excluded.events_path, current_pipeline_id=excluded.current_pipeline_id, created_at=excluded.created_at, updated_at=excluded.updated_at, root_relative_path=excluded.root_relative_path, last_import_at=excluded.last_import_at`).run(taskId, epochId, task.status, String((task.summary as JsonRecord).title), String((task.summary as JsonRecord).text), task.promptPath, task.eventsPath, nullable(task.currentPipelineId), task.createdAt, task.updatedAt, directoryName, importedAt);
      this.db.prepare("DELETE FROM pipelines WHERE task_id=?").run(taskId);
      for (const pipeline of pipelines) {
        this.db.prepare(`INSERT INTO pipelines(task_id, pipeline_id, ordinal, trigger, parent_pipeline_id, phase, state, started_at, updated_at, completed_at, metadata_path) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(taskId, pipeline.pipelineId, pipeline.ordinal, pipeline.trigger, nullable(pipeline.parentPipelineId), pipeline.phase, pipeline.state, pipeline.startedAt, pipeline.updatedAt, nullable(pipeline.completedAt), `pipelines/${pipeline.pipelineId}/pipeline.json`);
        for (const run of runs.filter((item) => item.pipelineId === pipeline.pipelineId)) {
          this.db.prepare(`INSERT INTO runs(task_id, pipeline_id, run_id, role, role_ordinal, session_id, resume_of_run_id, parent_run_id, retry_of_run_id, state, started_at, updated_at, completed_at, model, reasoning, metadata_path) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(taskId, pipeline.pipelineId, run.runId, run.role, run.roleOrdinal, run.sessionId, nullable(run.resumeOfRunId), nullable(run.parentRunId), nullable(run.retryOfRunId), run.state, run.startedAt, run.updatedAt, nullable(run.completedAt), nullable(run.model), nullable(run.reasoning), `pipelines/${pipeline.pipelineId}/runs/${run.runId}/run.json`);
          const usage = isRecord(run.usage) ? run.usage : {};
          const cost = isRecord(run.cost) ? run.cost : {};
          this.db.prepare(`INSERT INTO usage_facts(task_id, run_id, availability, prompt_tokens, completion_tokens, total_tokens, source_path, reason, cost_availability, estimated_micro_usd, cost_model, pricing_source, cost_reason) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(taskId, run.runId, usage.availability ?? "unavailable", safeInteger(usage.promptTokens), safeInteger(usage.completionTokens), safeInteger(usage.totalTokens), nullable(usage.sourcePath), nullable(usage.reason), cost.availability ?? "unavailable", safeInteger(cost.estimatedMicroUsd), nullable(cost.model), nullable(cost.pricingSource), nullable(cost.reason));
        }
      }
      const previousFiles = new Map(this.db.prepare("SELECT * FROM files WHERE task_id=?").all(taskId).map((row) => [String(row.relative_path), row]));
      this.db.prepare("DELETE FROM files WHERE task_id=?").run(taskId);
      for (const descriptor of descriptors) this.indexFile(taskId, root, descriptor, previousFiles.get(descriptor.path));
      this.indexFile(taskId, root, { path: "task.json", lifecycle: "live", availability: "available", mediaType: "application/json" }, previousFiles.get("task.json"));
      for (const pipeline of pipelines) { const path = `pipelines/${pipeline.pipelineId}/pipeline.json`; this.indexFile(taskId, root, { path, lifecycle: "live", availability: "available", mediaType: "application/json" }, previousFiles.get(path)); }
      for (const run of runs) { const path = `pipelines/${run.pipelineId}/runs/${run.runId}/run.json`; this.indexFile(taskId, root, { path, lifecycle: "live", availability: "available", mediaType: "application/json" }, previousFiles.get(path)); }
      if (existsSync(resolveSafePath(root, "manifest.json"))) this.indexFile(taskId, root, { path: "manifest.json", lifecycle: "terminal", availability: "available", mediaType: "application/json" }, previousFiles.get("manifest.json"));
      const archiveState = this.verifyManifest(taskId, root, task.status);
      this.db.prepare("UPDATE tasks SET archive_state=?, manifest_observed_at=?, verified_at=?, archive_reason=? WHERE task_id=?").run(archiveState.state, archiveState.manifestObservedAt, archiveState.verifiedAt, archiveState.reason, taskId);
      const changed = !previous || String(previous.status) !== String(task.status) || String(previous.updated_at) !== String(task.updatedAt) || String(previous.archive_state) !== archiveState.state;
      return { changed, archiveState: archiveState.state };
    });
    return result;
  }

  private indexFile(taskId: string, taskRoot: string, descriptor: FileDescriptor, previous?: Record<string, unknown>) {
    if (!isSafeRelativePath(descriptor.path)) return;
    let bytes: Buffer;
    let size = 0;
    try {
      const path = resolveSafePath(taskRoot, descriptor.path);
      const lexicalStat = lstatSync(path);
      if (lexicalStat.isSymbolicLink() || !lexicalStat.isFile()) throw new Error("not a regular file");
      bytes = readFileSync(path); size = bytes.length;
    } catch { this.db.prepare(`INSERT INTO files(task_id, relative_path, kind, media_type, lifecycle, declared_size, declared_sha256, status) VALUES(?, ?, ?, ?, ?, ?, ?, 'missing')`).run(taskId, descriptor.path, fileKind(descriptor.path), descriptor.mediaType ?? fileMediaType(descriptor.path), descriptor.lifecycle ?? "live", descriptor.byteSize ?? null, descriptor.sha256 ?? null); return; }
    const isJsonl = fileKind(descriptor.path) === "jsonl";
    let acceptedEnd = size;
    if (isJsonl) { const lastNewline = bytes.lastIndexOf(10); acceptedEnd = lastNewline < 0 ? 0 : lastNewline + 1; }
    const accepted = bytes.subarray(0, acceptedEnd);
    const prefixHash = hash(accepted);
    const prefixRevision = previous && previous.prefix_hash !== prefixHash ? Number(previous.prefix_revision ?? 0) + 1 : Number(previous?.prefix_revision ?? 0);
    const fileRevision = `${prefixRevision}:${size}:${prefixHash}`;
    this.db.prepare(`INSERT INTO files(task_id, relative_path, kind, media_type, lifecycle, declared_size, declared_sha256, actual_size, accepted_end, prefix_hash, prefix_revision, complete_records, file_revision, status) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, 'ready')`).run(taskId, descriptor.path, fileKind(descriptor.path), descriptor.mediaType ?? fileMediaType(descriptor.path), descriptor.lifecycle ?? "live", descriptor.byteSize ?? null, descriptor.sha256 ?? null, size, acceptedEnd, prefixHash, prefixRevision, fileRevision);
    if (!isJsonl) return;
    const lines = accepted.toString("utf8").split("\n");
    let start = 0;
    let ordinal = 0;
    for (const line of lines) {
      if (!line) { start += 1; continue; }
      const end = start + Buffer.byteLength(line) + 1;
      try {
        const value = JSON.parse(line) as JsonRecord;
        const timestamp = typeof value.at === "string" ? value.at : typeof value.timestamp === "string" ? value.timestamp : null;
        const recordType = typeof value.kind === "string" ? value.kind : typeof value.record_type === "string" ? value.record_type : typeof value.type === "string" ? value.type : null;
        this.db.prepare("INSERT INTO records(task_id, relative_path, ordinal, byte_start, byte_end, timestamp, record_type) VALUES(?, ?, ?, ?, ?, ?, ?)").run(taskId, descriptor.path, ordinal, start, end, timestamp, recordType);
        ordinal += 1;
      } catch { /* complete-line JSON parse failures remain opaque */ }
      start = end;
    }
    this.db.prepare("UPDATE files SET complete_records=? WHERE task_id=? AND relative_path=?").run(ordinal, taskId, descriptor.path);
  }

  private verifyManifest(taskId: string, taskRoot: string, taskStatus: unknown) {
    const manifestPath = resolveSafePath(taskRoot, "manifest.json");
    if (!existsSync(manifestPath)) return { state: "live", manifestObservedAt: null, verifiedAt: null, reason: null };
    const observed = now();
    let manifest: JsonRecord;
    try { manifest = parseCompleteJson(readFileSync(manifestPath, "utf8"), "manifest.json"); } catch { return { state: "incomplete", manifestObservedAt: observed, verifiedAt: null, reason: "manifest-invalid" }; }
    if (manifest.taskId !== taskId || !Array.isArray(manifest.files) || !TERMINAL_STATES.has(String(taskStatus))) return { state: "incomplete", manifestObservedAt: observed, verifiedAt: null, reason: "manifest-before-terminal" };
    for (const item of manifest.files) {
      if (!isRecord(item) || !isSafeRelativePath(item.path) || typeof item.byteSize !== "number" || typeof item.sha256 !== "string") return { state: "incomplete", manifestObservedAt: observed, verifiedAt: null, reason: "manifest-invalid" };
      try {
        const path = resolveSafePath(taskRoot, item.path);
        const lexicalStat = lstatSync(path);
        if (lexicalStat.isSymbolicLink() || !lexicalStat.isFile()) throw new Error("not a regular file");
        const file = readFileSync(path);
        if (file.length !== item.byteSize || hash(file) !== item.sha256) return { state: "corrupt", manifestObservedAt: observed, verifiedAt: null, reason: "manifest-mismatch" };
      } catch { return { state: "incomplete", manifestObservedAt: observed, verifiedAt: null, reason: "manifest-content-missing" }; }
    }
    return { state: "verified", manifestObservedAt: observed, verifiedAt: observed, reason: null };
  }
}

let singleton: StewardArchiveImporter | null = null;
export function getArchiveImporter(config?: ArchiveConfig) {
  const processState = globalThis as typeof globalThis & { __coquicStewardArchiveImporter?: StewardArchiveImporter };
  if (processState.__coquicStewardArchiveImporter) return processState.__coquicStewardArchiveImporter;
  if (!singleton) singleton = new StewardArchiveImporter(config);
  processState.__coquicStewardArchiveImporter = singleton;
  return singleton;
}
export function resetArchiveImporter() { const processState = globalThis as typeof globalThis & { __coquicStewardArchiveImporter?: StewardArchiveImporter }; singleton?.stop(); try { singleton?.db.close(); } catch { /* already closed */ } singleton = null; delete processState.__coquicStewardArchiveImporter; }

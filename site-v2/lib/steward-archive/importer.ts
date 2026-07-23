import { createHash, randomUUID } from "node:crypto";
import { createReadStream, existsSync, renameSync } from "node:fs";
import { open, readFile, readdir, stat } from "node:fs/promises";
import { watch as fsWatch, type FSWatcher } from "node:fs";
import { openArchiveDatabase, readDatabaseMeta, updateDatabaseMeta, withTransaction, type DatabaseMeta } from "./database";
import { getArchiveConfig, type ArchiveConfig } from "./config";
import { assertDirectoryRoot, isSafeId, isSafeRelativePath, resolveDirectoryContainedPath, resolveRegularContainedPath } from "./paths";
import { isRecord, parseCompleteJson, safeInteger, safeString, validateEpoch, validateManifest, validatePipeline, validateReview, validateRun, validateTask, validateValidation, type JsonRecord } from "./schema";
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

type IndexedRecord = { ordinal: number; byteStart: number; byteEnd: number; timestamp: string | null; recordType: string | null };
type RecordMode = "reuse" | "append" | "replace";
type FileSnapshot = FileDescriptor & { kind: string; status: "ready" | "missing"; size: number | null; acceptedEnd: number; prefixHash: string | null; prefixRevision: number; fileRevision: string; completeRecords: number; deviceId: string | null; inodeId: string | null; mtimeNs: string | null; ctimeNs: string | null; recordMode: RecordMode; parsedRecords: number };
type ArchiveVerification = { state: string; manifestObservedAt: string | null; verifiedAt: string | null; reason: string | null };

export interface ImportDiagnostics {
  jsonlFilesReused: number;
  jsonlFilesAppended: number;
  jsonlFilesRebuilt: number;
  jsonlRecordsParsed: number;
  recordRowsStaged: number;
}

const JSONL_NAMES = new Set(["events.jsonl", "codex.jsonl", "activities.jsonl", "manifest.jsonl"]);
const TERMINAL_STATES = new Set(["succeeded", "pushed", "no_changes", "blocked", "failed", "cancelled"]);

function now() { return new Date().toISOString(); }
function fileMediaType(path: string) {
  if (path.endsWith(".jsonl")) return "application/x-ndjson";
  if (path.endsWith(".json")) return "application/json";
  if (path.endsWith(".md")) return "text/markdown";
  if (path.endsWith(".diff")) return "text/x-diff";
  if (path.endsWith(".log")) return "text/plain";
  return "application/octet-stream";
}
function fileKind(path: string) { return JSONL_NAMES.has(path.split("/").at(-1) ?? "") ? "jsonl" : "artifact"; }
function nullable(value: unknown) { return value == null ? null : value; }
function yieldToEventLoop() { return new Promise<void>((resolve) => setImmediate(resolve)); }

async function findAcceptedEnd(path: string, size: number, kind: string) {
  if (kind !== "jsonl" || size === 0) return kind === "jsonl" ? 0 : size;
  const handle = await open(path, "r");
  try {
    const chunkSize = 64 * 1024;
    for (let end = size; end > 0;) {
      const start = Math.max(0, end - chunkSize);
      const buffer = Buffer.allocUnsafe(end - start);
      await handle.read(buffer, 0, buffer.length, start);
      const newline = buffer.lastIndexOf(10);
      if (newline !== -1) return start + newline + 1;
      end = start;
      await yieldToEventLoop();
    }
    return 0;
  } finally { await handle.close(); }
}

async function hashFilePrefix(path: string, end: number) {
  const digest = createHash("sha256");
  if (end > 0) for await (const chunk of createReadStream(path, { start: 0, end: end - 1, highWaterMark: 64 * 1024 })) { digest.update(chunk as Buffer); await yieldToEventLoop(); }
  return digest.digest("hex");
}

async function scanJsonl(path: string, start: number, acceptedEnd: number, startOrdinal: number, onRecords: (records: IndexedRecord[]) => void) {
  let firstRecordDigest: string | null = null;
  let lineDigest = createHash("sha256");
  let lineFragments: Buffer[] = [];
  let capturedBytes = 0;
  let offset = start;
  let lineStart = start;
  let ordinal = startOrdinal;
  let batch: IndexedRecord[] = [];
  const captureLimit = 64 * 1024;
  if (acceptedEnd > start) {
    for await (const value of createReadStream(path, { start, end: acceptedEnd - 1, highWaterMark: 64 * 1024 })) {
      const chunk = value as Buffer;
      let position = 0;
      while (position < chunk.length) {
        const newline = chunk.indexOf(10, position);
        const segmentEnd = newline === -1 ? chunk.length : newline;
        const segment = chunk.subarray(position, segmentEnd);
        lineDigest.update(segment);
        if (capturedBytes < captureLimit) {
          const captured = segment.subarray(0, captureLimit - capturedBytes);
          if (captured.length) lineFragments.push(captured);
          capturedBytes += captured.length;
        }
        if (newline === -1) break;
        lineDigest.update(Buffer.from("\n"));
        const byteEnd = offset + newline + 1;
        const line = capturedBytes < captureLimit ? Buffer.concat(lineFragments).toString("utf8") : "";
        let timestamp: string | null = null;
        let recordType: string | null = null;
        if (line) {
          try {
            const parsed = JSON.parse(line) as JsonRecord;
            timestamp = typeof parsed.at === "string" ? parsed.at : typeof parsed.timestamp === "string" ? parsed.timestamp : null;
            recordType = typeof parsed.kind === "string" ? parsed.kind : typeof parsed.record_type === "string" ? parsed.record_type : typeof parsed.type === "string" ? parsed.type : null;
          } catch { /* complete unknown records remain opaque */ }
        }
        const recordDigest = lineDigest.digest("hex");
        if (firstRecordDigest === null) firstRecordDigest = recordDigest;
        batch.push({ ordinal, byteStart: lineStart, byteEnd, timestamp, recordType });
        ordinal += 1;
        lineStart = byteEnd;
        lineDigest = createHash("sha256");
        lineFragments = [];
        capturedBytes = 0;
        position = newline + 1;
        if (batch.length === 512) { onRecords(batch); batch = []; await yieldToEventLoop(); }
      }
      offset += chunk.length;
      await yieldToEventLoop();
    }
  }
  if (batch.length) onRecords(batch);
  return { firstRecordDigest, completeRecords: ordinal, parsedRecords: ordinal - startOrdinal };
}

function descriptorFrom(value: unknown): FileDescriptor | null {
  if (!isRecord(value) || typeof value.path !== "string" || !isSafeRelativePath(value.path)) return null;
  return { path: value.path, lifecycle: safeString(value.lifecycle) ?? "live", availability: safeString(value.availability) ?? "available", mediaType: safeString(value.mediaType), byteSize: safeInteger(value.byteSize), sha256: safeString(value.sha256), requiredAtTerminal: value.requiredAtTerminal === true };
}

function collectDescriptors(task: JsonRecord, pipelines: Array<{ path: string; value: JsonRecord }>, runs: Array<{ path: string; value: JsonRecord }>, validations: Array<{ path: string; value: JsonRecord }>, reviews: Array<{ path: string; value: JsonRecord }>) {
  const descriptors = new Map<string, FileDescriptor>();
  const add = (value: unknown) => { const descriptor = descriptorFrom(value); if (descriptor) descriptors.set(descriptor.path, descriptor); };
  add({ path: "task.json", lifecycle: "live", availability: "available", mediaType: "application/json" });
  add({ path: task.promptPath, lifecycle: "terminal", availability: "available", mediaType: "text/markdown", requiredAtTerminal: true });
  add({ path: task.eventsPath, lifecycle: "live", availability: "available", mediaType: "application/x-ndjson", requiredAtTerminal: true });
  for (const item of pipelines) {
    add({ path: item.path, lifecycle: "live", availability: "available", mediaType: "application/json" });
    for (const key of ["inputs", "patches"]) if (Array.isArray(item.value[key])) for (const artifact of item.value[key]) add(artifact);
    if (isRecord(item.value.integration) && typeof item.value.integration.resultPath === "string") add({ path: item.value.integration.resultPath, lifecycle: "terminal", availability: item.value.integration.state === "unavailable" ? "unavailable" : "available", mediaType: "application/json", requiredAtTerminal: item.value.integration.state !== "pending" });
  }
  for (const item of validations) { add({ path: item.path, lifecycle: "live", availability: "available", mediaType: "application/json" }); add(item.value.output); }
  for (const item of reviews) { add({ path: item.path, lifecycle: "live", availability: "available", mediaType: "application/json" }); add(item.value.artifact); }
  for (const item of runs) {
    add({ path: item.path, lifecycle: "live", availability: "available", mediaType: "application/json" });
    if (isRecord(item.value.artifacts)) for (const descriptor of Object.values(item.value.artifacts)) add(descriptor);
  }
  return [...descriptors.values()];
}

async function readValidated(root: string, path: string, validator: (value: JsonRecord) => JsonRecord) {
  const resolved = await resolveRegularContainedPath(root, path);
  return validator(parseCompleteJson(await readFile(resolved.path, "utf8"), path));
}

function previousString(previous: Record<string, unknown> | undefined, key: string) {
  return previous?.[key] == null ? null : String(previous[key]);
}

async function indexSnapshot(taskRoot: string, descriptor: FileDescriptor, onRecords: (records: IndexedRecord[]) => void, previous?: Record<string, unknown>): Promise<FileSnapshot> {
  const kind = fileKind(descriptor.path);
  try {
    const resolved = await resolveRegularContainedPath(taskRoot, descriptor.path);
    const size = resolved.stat.size;
    const identity = await stat(resolved.path, { bigint: true });
    const deviceId = String(identity.dev);
    const inodeId = String(identity.ino);
    const mtimeNs = String(identity.mtimeNs);
    const ctimeNs = String(identity.ctimeNs);
    const unchanged = previous?.status === "ready"
      && Number(previous.actual_size) === size
      && previousString(previous, "device_id") === deviceId
      && previousString(previous, "inode_id") === inodeId
      && previousString(previous, "mtime_ns") === mtimeNs
      && previousString(previous, "ctime_ns") === ctimeNs;
    if (unchanged) {
      return {
        ...descriptor,
        kind,
        status: "ready",
        size,
        acceptedEnd: Number(previous.accepted_end),
        prefixHash: previousString(previous, "prefix_hash"),
        prefixRevision: Number(previous.prefix_revision),
        fileRevision: String(previous.file_revision),
        completeRecords: Number(previous.complete_records),
        deviceId,
        inodeId,
        mtimeNs,
        ctimeNs,
        recordMode: "reuse",
        parsedRecords: 0,
      };
    }
    const acceptedEnd = await findAcceptedEnd(resolved.path, size, kind);
    const previousEnd = Number(previous?.accepted_end ?? 0);
    const previousHash = typeof previous?.prefix_hash === "string" ? previous.prefix_hash : null;
    const sameFile = previous?.status === "ready" && previousString(previous, "device_id") === deviceId && previousString(previous, "inode_id") === inodeId;
    const appendCompatible = kind === "jsonl" && sameFile && acceptedEnd >= previousEnd && previousHash === await hashFilePrefix(resolved.path, previousEnd);
    const prefixRevision = previous ? Number(previous.prefix_revision ?? 0) + (appendCompatible ? 0 : 1) : 0;
    if (kind === "jsonl") {
      if (appendCompatible && acceptedEnd === previousEnd) {
        return { ...descriptor, kind, status: "ready", size, acceptedEnd, prefixHash: previousHash, prefixRevision, fileRevision: String(previous?.file_revision), completeRecords: Number(previous?.complete_records ?? 0), deviceId, inodeId, mtimeNs, ctimeNs, recordMode: "reuse", parsedRecords: 0 };
      }
      const start = appendCompatible ? previousEnd : 0;
      const startOrdinal = appendCompatible ? Number(previous?.complete_records ?? 0) : 0;
      const scanned = await scanJsonl(resolved.path, start, acceptedEnd, startOrdinal, onRecords);
      const prefixHash = await hashFilePrefix(resolved.path, acceptedEnd);
      const fileRevision = appendCompatible ? String(previous?.file_revision) : `sha256:${scanned.firstRecordDigest ?? prefixHash}`;
      return { ...descriptor, kind, status: "ready", size, acceptedEnd, prefixHash, prefixRevision, fileRevision, completeRecords: scanned.completeRecords, deviceId, inodeId, mtimeNs, ctimeNs, recordMode: appendCompatible ? "append" : "replace", parsedRecords: scanned.parsedRecords };
    }
    const prefixHash = await hashFilePrefix(resolved.path, acceptedEnd);
    return { ...descriptor, kind, status: "ready", size, acceptedEnd, prefixHash, prefixRevision, fileRevision: `sha256:${prefixHash}`, completeRecords: 0, deviceId, inodeId, mtimeNs, ctimeNs, recordMode: "replace", parsedRecords: 0 };
  } catch {
    return { ...descriptor, kind, status: "missing", size: null, acceptedEnd: 0, prefixHash: null, prefixRevision: Number(previous?.prefix_revision ?? 0) + (previous?.status === "ready" ? 1 : 0), fileRevision: String(previous?.file_revision ?? "sha256:missing"), completeRecords: 0, deviceId: null, inodeId: null, mtimeNs: null, ctimeNs: null, recordMode: "replace", parsedRecords: 0 };
  }
}

function preserveVerifiedTerminalEvidence(previousState: unknown, verification: ArchiveVerification): ArchiveVerification {
  if ((previousState !== "verified" && previousState !== "corrupt") || verification.state === "verified") return verification;
  return { ...verification, state: "corrupt", reason: verification.reason ?? "terminal-evidence-missing" };
}

async function listDurableFiles(taskRoot: string, relativeRoot = ""): Promise<string[]> {
  const root = relativeRoot ? await resolveDirectoryContainedPath(taskRoot, relativeRoot) : taskRoot;
  const entries = await readdir(root, { withFileTypes: true });
  const files: string[] = [];
  for (const entry of entries) {
    if (!isSafeId(entry.name)) throw new Error("archive contains an unsafe path");
    const path = relativeRoot ? `${relativeRoot}/${entry.name}` : entry.name;
    if (entry.isSymbolicLink()) throw new Error("archive contains a symlink");
    if (entry.isDirectory()) files.push(...await listDurableFiles(taskRoot, path));
    else if (entry.isFile() && path !== "manifest.json") files.push(path);
    else if (!entry.isFile()) throw new Error("archive contains a non-regular entry");
    if (files.length > 0 && files.length % 128 === 0) await yieldToEventLoop();
  }
  return files.sort();
}

async function verifyManifest(taskId: string, epochId: string, taskRoot: string, taskStatus: unknown): Promise<ArchiveVerification> {
  let manifestPath;
  try { manifestPath = await resolveRegularContainedPath(taskRoot, "manifest.json"); } catch { return { state: "live", manifestObservedAt: null, verifiedAt: null, reason: null }; }
  const observed = now();
  let manifest: JsonRecord;
  try { manifest = validateManifest(parseCompleteJson(await readFile(manifestPath.path, "utf8"), "manifest.json")); } catch { return { state: "incomplete", manifestObservedAt: observed, verifiedAt: null, reason: "manifest-invalid" }; }
  if (!TERMINAL_STATES.has(String(taskStatus)) || manifest.taskId !== taskId || manifest.epochId !== epochId || manifest.terminalStatus !== taskStatus) return { state: "incomplete", manifestObservedAt: observed, verifiedAt: null, reason: "manifest-identity" };
  let durableFiles: string[];
  try { durableFiles = await listDurableFiles(taskRoot); } catch { return { state: "corrupt", manifestObservedAt: observed, verifiedAt: null, reason: "manifest-tree-invalid" }; }
  const declared = (manifest.files as JsonRecord[]).map((item) => String(item.path));
  if (declared.length !== durableFiles.length || declared.some((path, index) => path !== durableFiles[index])) return { state: "incomplete", manifestObservedAt: observed, verifiedAt: null, reason: "manifest-file-set" };
  for (const item of manifest.files as JsonRecord[]) {
    try {
      const resolved = await resolveRegularContainedPath(taskRoot, String(item.path));
      if (resolved.stat.size !== item.byteSize || await hashFilePrefix(resolved.path, resolved.stat.size) !== item.sha256) return { state: "corrupt", manifestObservedAt: observed, verifiedAt: null, reason: "manifest-mismatch" };
    } catch { return { state: "incomplete", manifestObservedAt: observed, verifiedAt: null, reason: "manifest-content-missing" }; }
    await yieldToEventLoop();
  }
  return { state: "verified", manifestObservedAt: observed, verifiedAt: observed, reason: null };
}

export class StewardArchiveImporter {
  readonly config: ArchiveConfig;
  readonly db: DatabaseSync;
  private running = false;
  private queued = false;
  private watcher: FSWatcher | null = null;
  private timer: ReturnType<typeof setInterval> | null = null;
  private importDiagnostics: ImportDiagnostics = { jsonlFilesReused: 0, jsonlFilesAppended: 0, jsonlFilesRebuilt: 0, jsonlRecordsParsed: 0, recordRowsStaged: 0 };

  constructor(config = getArchiveConfig()) {
    this.config = config;
    try { this.db = openArchiveDatabase(config.cachePath); }
    catch {
      if (existsSync(config.cachePath)) {
        const stamp = Date.now();
        try { renameSync(config.cachePath, `${config.cachePath}.invalid-${stamp}`); } catch { /* a disposable cache may be replaced only when writable */ }
        for (const suffix of ["-wal", "-shm"]) if (existsSync(`${config.cachePath}${suffix}`)) try { renameSync(`${config.cachePath}${suffix}`, `${config.cachePath}.invalid-${stamp}${suffix}`); } catch { /* sidecar is disposable */ }
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

  revision() { const meta = readDatabaseMeta(this.db); return { revision: meta.revision, state: meta.state as ImportState }; }

  diagnostics() { return { ...this.importDiagnostics }; }

  start() {
    if (this.watcher || this.timer) return;
    try { this.watcher = fsWatch(this.config.tasksRoot, { recursive: true }, () => { void this.requestReconcile(); }); updateDatabaseMeta(this.db, { watchState: "watching" }); }
    catch { updateDatabaseMeta(this.db, { watchState: "unavailable" }); }
    this.timer = setInterval(() => { void this.requestReconcile(); }, this.config.reconcileMs); this.timer.unref?.();
    void this.requestReconcile();
  }

  stop() { this.watcher?.close(); this.watcher = null; if (this.timer) clearInterval(this.timer); this.timer = null; }

  async requestReconcile() {
    if (this.running) { this.queued = true; return; }
    this.running = true;
    try { await this.reconcile(); } finally { this.running = false; if (this.queued) { this.queued = false; void this.requestReconcile(); } }
  }

  async reconcile() {
    const diagnostics: ImportDiagnostics = { jsonlFilesReused: 0, jsonlFilesAppended: 0, jsonlFilesRebuilt: 0, jsonlRecordsParsed: 0, recordRowsStaged: 0 };
    this.importDiagnostics = diagnostics;
    updateDatabaseMeta(this.db, { lastAttemptAt: now() });
    const started = Date.now();
    if (!existsSync(this.config.tasksRoot)) { updateDatabaseMeta(this.db, { state: "unavailable", lastErrorCategory: "archive-root-missing", lastErrorCount: 1 }); return; }
    try { await assertDirectoryRoot(this.config.tasksRoot); } catch { updateDatabaseMeta(this.db, { state: "unavailable", lastErrorCategory: "archive-root-invalid", lastErrorCount: 1 }); return; }
    let epoch: ReturnType<typeof validateEpoch>;
    try { epoch = validateEpoch(parseCompleteJson(await readFile((await resolveRegularContainedPath(this.config.tasksRoot, "epoch.json")).path, "utf8"), "epoch.json")); }
    catch { const previous = readDatabaseMeta(this.db).epochId; updateDatabaseMeta(this.db, { state: previous ? "degraded" : "unavailable", lastErrorCategory: "epoch-unavailable", lastErrorCount: 1 }); return; }
    const previousMeta = readDatabaseMeta(this.db);
    if (previousMeta.epochId && previousMeta.epochId !== epoch.epochId) { updateDatabaseMeta(this.db, { state: "incompatible", lastErrorCategory: "epoch-changed", lastErrorCount: 1 }); return; }
    updateDatabaseMeta(this.db, { epochId: epoch.epochId, state: "indexing" });
    let changed = false;
    let failures = 0;
    let archiveCorrupt = false;
    let entries;
    try { entries = await readdir(this.config.tasksRoot, { withFileTypes: true }); } catch { updateDatabaseMeta(this.db, { state: "degraded", lastErrorCategory: "archive-read", lastErrorCount: 1 }); return; }
    let processed = 0;
    for (const entry of entries) {
      if (!entry.isDirectory() || entry.name.startsWith(".") || !isSafeId(entry.name)) continue;
      try {
        const result = await this.importTask(entry.name, epoch.epochId, diagnostics);
        changed ||= result.changed;
        archiveCorrupt ||= result.archiveState === "corrupt";
        this.db.prepare("DELETE FROM importer_errors WHERE task_id=?").run(entry.name);
      } catch {
        failures += 1;
        const retained = await this.reverifyRetainedTerminalTask(entry.name, epoch.epochId);
        changed ||= retained.changed;
        archiveCorrupt ||= retained.archiveState === "corrupt";
        this.recordError(entry.name, "task-import");
      }
      processed += 1;
      if (processed % this.config.batchSize === 0) await yieldToEventLoop();
    }
    const finalState: ImportState = archiveCorrupt ? "archive-corrupt" : failures ? "degraded" : "ready";
    const meta = readDatabaseMeta(this.db);
    updateDatabaseMeta(this.db, { state: finalState, lastSuccessAt: now(), lastErrorCategory: failures ? "task-import" : null, lastErrorCount: failures, revision: meta.revision + (changed ? 1 : 0), lastScanDurationMs: Date.now() - started });
  }

  private recordError(taskId: string | null, category: string) {
    const timestamp = now();
    this.db.prepare(`INSERT INTO importer_errors(task_id, category, count, first_seen_at, last_seen_at) VALUES(?, ?, 1, ?, ?) ON CONFLICT(task_id, category) DO UPDATE SET count=min(count+1, 1000), last_seen_at=excluded.last_seen_at`).run(taskId, category, timestamp, timestamp);
  }

  private async reverifyRetainedTerminalTask(directoryName: string, epochId: string) {
    const row = this.db.prepare("SELECT task_id, status, archive_state FROM tasks WHERE root_relative_path=?").get(directoryName);
    if (!row || !TERMINAL_STATES.has(String(row.status))) return { changed: false, archiveState: String(row?.archive_state ?? "live") };
    let verification: ArchiveVerification;
    try {
      const root = await resolveDirectoryContainedPath(this.config.tasksRoot, directoryName);
      verification = preserveVerifiedTerminalEvidence(row.archive_state, await verifyManifest(String(row.task_id), epochId, root, row.status));
    } catch {
      verification = { state: "corrupt", manifestObservedAt: now(), verifiedAt: null, reason: "terminal-tree-invalid" };
    }
    const previous = String(row.archive_state);
    this.db.prepare("UPDATE tasks SET archive_state=?, manifest_observed_at=?, verified_at=?, archive_reason=? WHERE task_id=?").run(verification.state, verification.manifestObservedAt, verification.verifiedAt, verification.reason, row.task_id);
    return { changed: previous !== verification.state, archiveState: verification.state };
  }

  private async importTask(directoryName: string, epochId: string, diagnostics: ImportDiagnostics) {
    const root = await resolveDirectoryContainedPath(this.config.tasksRoot, directoryName);
    const task = await readValidated(root, "task.json", validateTask);
    const taskId = String(task.taskId);
    if (task.epochId !== epochId) throw new Error("task identity mismatch");
    const previousTask = this.db.prepare("SELECT status, title, summary, updated_at, archive_state FROM tasks WHERE task_id=?").get(taskId);
    const pipelines: Array<{ path: string; value: JsonRecord }> = [];
    const runs: Array<{ path: string; value: JsonRecord }> = [];
    const validations: Array<{ path: string; value: JsonRecord }> = [];
    const reviews: Array<{ path: string; value: JsonRecord }> = [];
    for (const ref of task.pipelines as JsonRecord[]) {
      const path = String(ref.path);
      const pipeline = await readValidated(root, path, validatePipeline);
      if (pipeline.taskId !== taskId || pipeline.pipelineId !== ref.pipelineId) throw new Error("pipeline identity mismatch");
      pipelines.push({ path, value: pipeline });
      for (const runRef of pipeline.runs as JsonRecord[]) {
        const runPath = String(runRef.path);
        const run = await readValidated(root, runPath, validateRun);
        if (run.taskId !== taskId || run.pipelineId !== pipeline.pipelineId || run.runId !== runRef.runId) throw new Error("run identity mismatch");
        runs.push({ path: runPath, value: run });
      }
      for (const validationRef of pipeline.validations as JsonRecord[]) {
        const validationPath = String(validationRef.path);
        const validation = await readValidated(root, validationPath, validateValidation);
        if (validation.taskId !== taskId || validation.pipelineId !== pipeline.pipelineId || validation.validationId !== validationRef.validationId) throw new Error("validation identity mismatch");
        validations.push({ path: validationPath, value: validation });
      }
      for (const reviewRef of pipeline.reviews as JsonRecord[]) {
        const reviewPath = String(reviewRef.path);
        const review = await readValidated(root, reviewPath, validateReview);
        if (review.taskId !== taskId || review.pipelineId !== pipeline.pipelineId || review.reviewId !== reviewRef.reviewId || review.kind !== reviewRef.kind) throw new Error("review identity mismatch");
        reviews.push({ path: reviewPath, value: review });
      }
    }

    const descriptors = collectDescriptors(task, pipelines, runs, validations, reviews);
    try { await resolveRegularContainedPath(root, "manifest.json"); descriptors.push({ path: "manifest.json", lifecycle: "terminal", availability: "available", mediaType: "application/json" }); } catch { /* live tasks need no manifest */ }
    const previousFiles = new Map(this.db.prepare("SELECT * FROM files WHERE task_id=?").all(taskId).map((row) => [String(row.relative_path), row]));
    const snapshots: FileSnapshot[] = [];
    const importToken = randomUUID();
    const insertStage = this.db.prepare("INSERT INTO record_staging(import_token, task_id, relative_path, ordinal, byte_start, byte_end, timestamp, record_type) VALUES(?, ?, ?, ?, ?, ?, ?, ?)");
    try {
      for (const descriptor of descriptors) {
        const stageRecords = (records: IndexedRecord[]) => withTransaction(this.db, () => {
          for (const record of records) insertStage.run(importToken, taskId, descriptor.path, record.ordinal, record.byteStart, record.byteEnd, record.timestamp, record.recordType);
        });
        const snapshot = await indexSnapshot(root, descriptor, (records) => { diagnostics.recordRowsStaged += records.length; stageRecords(records); }, previousFiles.get(descriptor.path));
        snapshots.push(snapshot);
        if (snapshot.kind === "jsonl") {
          diagnostics.jsonlRecordsParsed += snapshot.parsedRecords;
          if (snapshot.recordMode === "reuse") diagnostics.jsonlFilesReused += 1;
          else if (snapshot.recordMode === "append") diagnostics.jsonlFilesAppended += 1;
          else diagnostics.jsonlFilesRebuilt += 1;
        }
        if (snapshots.length % 32 === 0) await yieldToEventLoop();
      }
      const archiveState = preserveVerifiedTerminalEvidence(previousTask?.archive_state, await verifyManifest(taskId, epochId, root, task.status));
      const importedAt = now();
      return withTransaction(this.db, () => {
      const previous = previousTask;
      const previousRunCount = Number(this.db.prepare("SELECT count(*) AS count FROM runs WHERE task_id=?").get(taskId)?.count ?? 0);
      const previousPipelineCount = Number(this.db.prepare("SELECT count(*) AS count FROM pipelines WHERE task_id=?").get(taskId)?.count ?? 0);
      const fileChanged = snapshots.length !== previousFiles.size || snapshots.some((item) => { const old = previousFiles.get(item.path); return !old || String(old.status) !== item.status || Number(old.actual_size ?? -1) !== (item.size ?? -1) || Number(old.accepted_end) !== item.acceptedEnd || String(old.prefix_hash ?? "") !== String(item.prefixHash ?? "") || String(old.declared_sha256 ?? "") !== String(item.sha256 ?? ""); });
      this.db.prepare(`INSERT INTO tasks(task_id, epoch_id, status, title, summary, prompt_path, events_path, current_pipeline_id, created_at, updated_at, root_relative_path, last_import_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(task_id) DO UPDATE SET epoch_id=excluded.epoch_id, status=excluded.status, title=excluded.title, summary=excluded.summary, prompt_path=excluded.prompt_path, events_path=excluded.events_path, current_pipeline_id=excluded.current_pipeline_id, created_at=excluded.created_at, updated_at=excluded.updated_at, root_relative_path=excluded.root_relative_path, last_import_at=excluded.last_import_at`).run(taskId, epochId, task.status, String((task.summary as JsonRecord).title), String((task.summary as JsonRecord).text), task.promptPath, task.eventsPath, nullable(task.currentPipelineId), task.createdAt, task.updatedAt, directoryName, importedAt);
      this.db.prepare("DELETE FROM usage_facts WHERE task_id=?").run(taskId);
      this.db.prepare("DELETE FROM pipelines WHERE task_id=?").run(taskId);
      for (const item of pipelines) {
        const pipeline = item.value;
        this.db.prepare(`INSERT INTO pipelines(task_id, pipeline_id, ordinal, trigger, parent_pipeline_id, phase, state, started_at, updated_at, completed_at, metadata_path) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(taskId, pipeline.pipelineId, pipeline.ordinal, pipeline.trigger, nullable(pipeline.parentPipelineId), pipeline.phase, pipeline.state, pipeline.startedAt, pipeline.updatedAt, nullable(pipeline.completedAt), item.path);
        for (const runItem of runs.filter((candidate) => candidate.value.pipelineId === pipeline.pipelineId)) {
          const run = runItem.value;
          this.db.prepare(`INSERT INTO runs(task_id, pipeline_id, run_id, role, role_ordinal, session_id, resume_of_run_id, parent_run_id, retry_of_run_id, state, started_at, updated_at, completed_at, model, reasoning, metadata_path) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(taskId, pipeline.pipelineId, run.runId, run.role, run.roleOrdinal, run.sessionId, nullable(run.resumeOfRunId), nullable(run.parentRunId), nullable(run.retryOfRunId), run.state, run.startedAt, run.updatedAt, nullable(run.completedAt), nullable(run.model), nullable(run.reasoning), runItem.path);
          const usage = isRecord(run.usage) ? run.usage : {};
          const cost = isRecord(run.cost) ? run.cost : {};
          this.db.prepare(`INSERT INTO usage_facts(task_id, run_id, availability, prompt_tokens, completion_tokens, total_tokens, source_path, reason, cost_availability, estimated_micro_usd, cost_model, pricing_source, cost_reason) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(taskId, run.runId, usage.availability ?? "unavailable", safeInteger(usage.promptTokens), safeInteger(usage.completionTokens), safeInteger(usage.totalTokens), nullable(usage.sourcePath), nullable(usage.reason), cost.availability ?? "unavailable", safeInteger(cost.estimatedMicroUsd), nullable(cost.model), nullable(cost.pricingSource), nullable(cost.reason));
        }
      }
      const currentPaths = new Set(snapshots.map((file) => file.path));
      for (const oldPath of previousFiles.keys()) if (!currentPaths.has(oldPath)) this.db.prepare("DELETE FROM files WHERE task_id=? AND relative_path=?").run(taskId, oldPath);
      for (const file of snapshots) {
        this.db.prepare(`INSERT INTO files(task_id, relative_path, kind, media_type, lifecycle, declared_size, declared_sha256, actual_size, accepted_end, prefix_hash, prefix_revision, complete_records, file_revision, device_id, inode_id, mtime_ns, ctime_ns, status) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(task_id, relative_path) DO UPDATE SET kind=excluded.kind, media_type=excluded.media_type, lifecycle=excluded.lifecycle, declared_size=excluded.declared_size, declared_sha256=excluded.declared_sha256, actual_size=excluded.actual_size, accepted_end=excluded.accepted_end, prefix_hash=excluded.prefix_hash, prefix_revision=excluded.prefix_revision, complete_records=excluded.complete_records, file_revision=excluded.file_revision, device_id=excluded.device_id, inode_id=excluded.inode_id, mtime_ns=excluded.mtime_ns, ctime_ns=excluded.ctime_ns, status=excluded.status`).run(taskId, file.path, file.kind, file.mediaType ?? fileMediaType(file.path), file.lifecycle ?? "live", file.byteSize ?? null, file.sha256 ?? null, file.size, file.acceptedEnd, file.prefixHash, file.prefixRevision, file.completeRecords, file.fileRevision, file.deviceId, file.inodeId, file.mtimeNs, file.ctimeNs, file.status);
        if (file.recordMode === "replace") this.db.prepare("DELETE FROM records WHERE task_id=? AND relative_path=?").run(taskId, file.path);
        if (file.recordMode !== "reuse" && file.completeRecords) this.db.prepare("INSERT OR REPLACE INTO records(task_id, relative_path, ordinal, byte_start, byte_end, timestamp, record_type) SELECT task_id, relative_path, ordinal, byte_start, byte_end, timestamp, record_type FROM record_staging WHERE import_token=? AND relative_path=? ORDER BY ordinal").run(importToken, file.path);
      }
      this.db.prepare("DELETE FROM record_staging WHERE import_token=?").run(importToken);
      this.db.prepare("UPDATE tasks SET archive_state=?, manifest_observed_at=?, verified_at=?, archive_reason=? WHERE task_id=?").run(archiveState.state, archiveState.manifestObservedAt, archiveState.verifiedAt, archiveState.reason, taskId);
      const changed = !previous || String(previous.status) !== String(task.status) || String(previous.title) !== String((task.summary as JsonRecord).title) || String(previous.summary) !== String((task.summary as JsonRecord).text) || String(previous.updated_at) !== String(task.updatedAt) || String(previous.archive_state) !== archiveState.state || previousRunCount !== runs.length || previousPipelineCount !== pipelines.length || fileChanged;
        return { changed, archiveState: archiveState.state };
      });
    } finally {
      this.db.prepare("DELETE FROM record_staging WHERE import_token=?").run(importToken);
    }
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

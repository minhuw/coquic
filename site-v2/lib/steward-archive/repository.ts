import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { open, type FileHandle } from "node:fs/promises";
import { basename } from "node:path";
import { Readable } from "node:stream";
import type { DatabaseSync } from "node:sqlite";
import { getArchiveConfig, type ArchiveConfig } from "./config";
import { getArchiveImporter, type ImportStatus, type StewardArchiveImporter } from "./importer";
import { isSafeId, isSafeRelativePath, resolveDirectoryContainedPath, resolveRegularContainedPath } from "./paths";
import { isRecord, parseCompleteJson, validateControlEvent, validatePipeline, validateRun, validateTask, validateValidation, validateReview, type JsonRecord } from "./schema";
import { openControlArtifact } from "./control-loop";

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

export interface DomainHealth {
  domain: "tasks" | "control-loop";
  state: string;
  epochId: string | null;
  lastAttemptAt: string | null;
  lastSuccessAt: string | null;
  lastErrorCategory: string | null;
  lagSeconds: number | null;
}

export interface SignalRow {
  signalId: string;
  provider: string;
  fingerprint: string;
  status: string;
  createdAt: string;
  updatedAt: string;
  observationCount: number;
  plannerRunCount: number;
  taskCount: number;
}

export interface PlannerRunRow {
  plannerRunId: string;
  state: string;
  startedAt: string;
  completedAt: string | null;
  proposalCount: number;
  inputSignalCount: number;
  taskCount: number;
}

export interface ControlPage<T> { items: T[]; nextCursor: string | null; previousCursor: string | null; total: number; revision: number; }

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

function renderPlannerValue(source: string) {
  let value: JsonRecord;
  try { value = JSON.parse(source) as JsonRecord; } catch { return { opaque: true, category: "unrecognized-record" }; }
  if (!isRecord(value)) return { opaque: true, category: "unrecognized-record" };
  return value;
}

async function readJsonlPage(handle: FileHandle, start: number, end: number, limit: number) {
  const buffer = Buffer.allocUnsafe(64 * 1024);
  const records: JsonRecord[] = [];
  let fragments: Buffer[] = [];
  let position = start;
  let nextOffset = start;
  let reachedLimit = false;
  while (position < end && !reachedLimit) {
    const length = Math.min(buffer.length, end - position);
    const { bytesRead } = await handle.read(buffer, 0, length, position);
    if (bytesRead !== length) throw staleCursor("accepted planner transcript changed");
    let chunkPosition = 0;
    while (chunkPosition < bytesRead) {
      const newline = buffer.indexOf(10, chunkPosition);
      const segmentEnd = newline < 0 || newline >= bytesRead ? bytesRead : newline;
      fragments.push(Buffer.from(buffer.subarray(chunkPosition, segmentEnd)));
      if (newline < 0 || newline >= bytesRead) break;
      const source = Buffer.concat(fragments).toString("utf8");
      nextOffset = position + newline + 1;
      fragments = [];
      chunkPosition = newline + 1;
      if (source.length > 0) records.push(renderPlannerValue(source));
      if (records.length >= limit) { reachedLimit = true; break; }
    }
    position += bytesRead;
    await yieldToEventLoop();
  }
  return {
    records,
    nextOffset,
    hasMore: reachedLimit && nextOffset < end,
    incompleteTail: !reachedLimit && position >= end && fragments.length > 0,
  };
}

export class StewardArchiveRepository {
  readonly importer: StewardArchiveImporter;
  readonly config: ArchiveConfig;
  readonly db: DatabaseSync;

  constructor(importer = getArchiveImporter()) { this.importer = importer; this.config = importer.config; this.db = importer.db; }

  getImportStatus(): ImportStatus { return this.importer.status(); }
  getRevision() { return this.importer.revision(); }

  getDomainHealth(): DomainHealth[] {
    const rows = this.db.prepare("SELECT domain, state, epoch_id, last_attempt_at, last_success_at, last_error_category, lag_seconds FROM domain_health ORDER BY domain").all();
    const task = this.getImportStatus();
    const result: DomainHealth[] = rows.filter((row) => row.domain === "tasks" || row.domain === "control-loop").map((row) => ({ domain: String(row.domain) as DomainHealth["domain"], state: String(row.state), epochId: row.epoch_id == null ? null : String(row.epoch_id), lastAttemptAt: row.last_attempt_at == null ? null : String(row.last_attempt_at), lastSuccessAt: row.last_success_at == null ? null : String(row.last_success_at), lastErrorCategory: row.last_error_category == null ? null : String(row.last_error_category), lagSeconds: row.lag_seconds == null ? null : Number(row.lag_seconds) }));
    if (!result.some((item) => item.domain === "tasks")) result.push({ domain: "tasks", state: task.state, epochId: task.epochId, lastAttemptAt: task.lastAttemptAt, lastSuccessAt: task.lastSuccessAt, lastErrorCategory: task.lastErrorCategory, lagSeconds: task.lagSeconds });
    if (!result.some((item) => item.domain === "control-loop")) result.push({ domain: "control-loop", state: "unavailable", epochId: null, lastAttemptAt: null, lastSuccessAt: null, lastErrorCategory: "root-unconfigured", lagSeconds: null });
    return result;
  }

  getControlLoopStatus() {
    const control = this.getDomainHealth().find((item) => item.domain === "control-loop")!;
    const counts = {
      fetches: Number(this.db.prepare("SELECT count(*) AS count FROM control_fetches").get()?.count ?? 0),
      observations: Number(this.db.prepare("SELECT count(*) AS count FROM control_observations").get()?.count ?? 0),
      signals: Number(this.db.prepare("SELECT count(*) AS count FROM control_signals").get()?.count ?? 0),
      plannerRuns: Number(this.db.prepare("SELECT count(*) AS count FROM control_planner_runs").get()?.count ?? 0),
      proposals: Number(this.db.prepare("SELECT count(*) AS count FROM control_proposals").get()?.count ?? 0),
      edges: Number(this.db.prepare("SELECT count(*) AS count FROM control_edges").get()?.count ?? 0),
      pendingLinks: Number(this.db.prepare("SELECT count(*) AS count FROM control_pending_links").get()?.count ?? 0),
    };
    const current = this.db.prepare("SELECT generated_at, fetch_count, observation_count, signal_count, planner_run_count, pending_signal_count, active_planner_run_id, status FROM control_current WHERE singleton=1").get();
    return { state: control.state, epochId: control.epochId, revision: this.getRevision().revision, freshness: control, counts, current: current ? { generatedAt: String(current.generated_at), fetches: current.fetch_count == null ? null : Number(current.fetch_count), observations: current.observation_count == null ? null : Number(current.observation_count), signals: current.signal_count == null ? null : Number(current.signal_count), plannerRuns: current.planner_run_count == null ? null : Number(current.planner_run_count), pendingSignals: current.pending_signal_count == null ? null : Number(current.pending_signal_count), activePlannerRunId: current.active_planner_run_id == null ? null : String(current.active_planner_run_id), status: String(current.status) } : null };
  }

  private controlRevision() { return this.getRevision().revision; }

  listSignalsPage(cursor?: string | null, limit = 50): ControlPage<SignalRow> {
    const bounded = Math.min(50, Math.max(1, limit));
    const decoded = cursor ? decodeCursor(cursor) : null;
    if (decoded && (decoded.scope !== "signals" || typeof decoded.revision !== "number" || decoded.revision !== this.controlRevision() || !["next", "previous"].includes(String(decoded.direction)))) throw staleCursor("signal list cursor is stale");
    let rows: Array<Record<string, unknown>>;
    if (!decoded) rows = this.db.prepare(`SELECT s.*, (SELECT count(*) FROM control_observations o WHERE o.canonical_signal_id=s.signal_id) AS observation_count, (SELECT count(*) FROM control_edges e WHERE e.edge_type='signal_planner_run' AND e.source_id=s.signal_id) AS planner_run_count, (SELECT count(*) FROM control_edges e JOIN control_proposals p ON p.proposal_id=e.target_id JOIN tasks t ON t.task_id=p.task_id WHERE e.edge_type='signal_proposal' AND e.source_id=s.signal_id) AS task_count FROM control_signals s ORDER BY s.updated_at DESC, s.signal_id DESC LIMIT ?`).all(bounded);
    else {
      if (typeof decoded.updatedAt !== "string" || typeof decoded.signalId !== "string" || !isSafeId(decoded.signalId)) throw invalidCursor();
      const updatedAt = decoded.updatedAt; const signalId = decoded.signalId;
      const taskCount = "(SELECT count(DISTINCT p.task_id) FROM control_edges e JOIN control_proposals p ON p.proposal_id=e.target_id JOIN tasks t ON t.task_id=p.task_id WHERE e.edge_type='signal_proposal' AND e.source_id=s.signal_id) AS task_count";
      if (decoded.direction === "next") rows = this.db.prepare(`SELECT s.*, (SELECT count(*) FROM control_observations o WHERE o.canonical_signal_id=s.signal_id) AS observation_count, (SELECT count(*) FROM control_edges e WHERE e.edge_type='signal_planner_run' AND e.source_id=s.signal_id) AS planner_run_count, ${taskCount} FROM control_signals s WHERE (s.updated_at < ? OR (s.updated_at=? AND s.signal_id<?)) ORDER BY s.updated_at DESC, s.signal_id DESC LIMIT ?`).all(updatedAt, updatedAt, signalId, bounded);
      else rows = this.db.prepare(`SELECT s.*, (SELECT count(*) FROM control_observations o WHERE o.canonical_signal_id=s.signal_id) AS observation_count, (SELECT count(*) FROM control_edges e WHERE e.edge_type='signal_planner_run' AND e.source_id=s.signal_id) AS planner_run_count, ${taskCount} FROM control_signals s WHERE (s.updated_at > ? OR (s.updated_at=? AND s.signal_id>?)) ORDER BY s.updated_at ASC, s.signal_id ASC LIMIT ?`).all(updatedAt, updatedAt, signalId, bounded).reverse();
    }
    const items = rows.map((row) => ({ signalId: String(row.signal_id), provider: String(row.provider), fingerprint: String(row.fingerprint), status: String(row.status), createdAt: String(row.created_at), updatedAt: String(row.updated_at), observationCount: Number(row.observation_count ?? 0), plannerRunCount: Number(row.planner_run_count ?? 0), taskCount: Number(row.task_count ?? 0) }));
    const first = items[0]; const last = items.at(-1); const total = Number(this.db.prepare("SELECT count(*) AS count FROM control_signals").get()?.count ?? 0); const revision = this.controlRevision();
    const next = last && Boolean(this.db.prepare("SELECT 1 FROM control_signals WHERE updated_at < ? OR (updated_at=? AND signal_id<?) LIMIT 1").get(last.updatedAt, last.updatedAt, last.signalId)) ? encodeCursor({ scope: "signals", direction: "next", updatedAt: last.updatedAt, signalId: last.signalId, revision }) : null;
    const previous = first && Boolean(this.db.prepare("SELECT 1 FROM control_signals WHERE updated_at > ? OR (updated_at=? AND signal_id>? ) LIMIT 1").get(first.updatedAt, first.updatedAt, first.signalId)) ? encodeCursor({ scope: "signals", direction: "previous", updatedAt: first.updatedAt, signalId: first.signalId, revision }) : null;
    return { items, nextCursor: next, previousCursor: previous, total, revision };
  }

  listPlannerRunsPage(cursor?: string | null, limit = 50): ControlPage<PlannerRunRow> {
    const bounded = Math.min(50, Math.max(1, limit));
    const decoded = cursor ? decodeCursor(cursor) : null;
    if (decoded && (decoded.scope !== "planner-runs" || typeof decoded.revision !== "number" || decoded.revision !== this.controlRevision() || !["next", "previous"].includes(String(decoded.direction)))) throw staleCursor("planner-run list cursor is stale");
    let rows: Array<Record<string, unknown>>;
    if (!decoded) rows = this.db.prepare(`SELECT r.*, (SELECT count(*) FROM control_proposals p WHERE p.planner_run_id=r.planner_run_id) AS proposal_count, (SELECT json_array_length(r.input_signal_ids)) AS input_signal_count, (SELECT count(DISTINCT p.task_id) FROM control_proposals p WHERE p.planner_run_id=r.planner_run_id AND p.task_id IS NOT NULL) AS task_count FROM control_planner_runs r ORDER BY r.started_at DESC, r.planner_run_id DESC LIMIT ?`).all(bounded);
    else {
      if (typeof decoded.startedAt !== "string" || typeof decoded.plannerRunId !== "string" || !isSafeId(decoded.plannerRunId)) throw invalidCursor();
      const startedAt = decoded.startedAt; const runId = decoded.plannerRunId;
      const query = `SELECT r.*, (SELECT count(*) FROM control_proposals p WHERE p.planner_run_id=r.planner_run_id) AS proposal_count, (SELECT json_array_length(r.input_signal_ids)) AS input_signal_count, (SELECT count(DISTINCT p.task_id) FROM control_proposals p WHERE p.planner_run_id=r.planner_run_id AND p.task_id IS NOT NULL) AS task_count FROM control_planner_runs r WHERE (r.started_at ${decoded.direction === "next" ? "<" : ">"} ? OR (r.started_at=? AND r.planner_run_id ${decoded.direction === "next" ? "<" : ">"} ?)) ORDER BY r.started_at ${decoded.direction === "next" ? "DESC" : "ASC"}, r.planner_run_id ${decoded.direction === "next" ? "DESC" : "ASC"} LIMIT ?`;
      rows = this.db.prepare(query).all(startedAt, startedAt, runId, bounded); if (decoded.direction === "previous") rows.reverse();
    }
    const items = rows.map((row) => ({ plannerRunId: String(row.planner_run_id), state: String(row.state), startedAt: String(row.started_at), completedAt: row.completed_at == null ? null : String(row.completed_at), proposalCount: Number(row.proposal_count ?? 0), inputSignalCount: Number(row.input_signal_count ?? 0), taskCount: Number(row.task_count ?? 0) }));
    const first = items[0]; const last = items.at(-1); const total = Number(this.db.prepare("SELECT count(*) AS count FROM control_planner_runs").get()?.count ?? 0); const revision = this.controlRevision();
    const next = last && Boolean(this.db.prepare("SELECT 1 FROM control_planner_runs WHERE started_at < ? OR (started_at=? AND planner_run_id<?) LIMIT 1").get(last.startedAt, last.startedAt, last.plannerRunId)) ? encodeCursor({ scope: "planner-runs", direction: "next", startedAt: last.startedAt, plannerRunId: last.plannerRunId, revision }) : null;
    const previous = first && Boolean(this.db.prepare("SELECT 1 FROM control_planner_runs WHERE started_at > ? OR (started_at=? AND planner_run_id>? ) LIMIT 1").get(first.startedAt, first.startedAt, first.plannerRunId)) ? encodeCursor({ scope: "planner-runs", direction: "previous", startedAt: first.startedAt, plannerRunId: first.plannerRunId, revision }) : null;
    return { items, nextCursor: next, previousCursor: previous, total, revision };
  }

  getSignalDetail(signalId: string) {
    if (!isSafeId(signalId)) return null;
    const signal = this.db.prepare("SELECT * FROM control_signals WHERE signal_id=?").get(signalId);
    if (!signal) return null;
    const observations = this.db.prepare("SELECT observation_id, fetch_id, provider, kind, fingerprint, title, summary, severity, canonical_signal_id, dedupe_result, observed_at, event_id FROM control_observations WHERE canonical_signal_id=? ORDER BY observed_at, observation_id").all(signalId).map((row) => ({ observationId: String(row.observation_id), fetchId: String(row.fetch_id), provider: String(row.provider), kind: String(row.kind), fingerprint: String(row.fingerprint), title: String(row.title), summary: String(row.summary), severity: row.severity == null ? null : String(row.severity), canonicalSignalId: String(row.canonical_signal_id), dedupeResult: String(row.dedupe_result), observedAt: String(row.observed_at), eventId: String(row.event_id) }));
    const transitions = this.db.prepare("SELECT transition_id, signal_id, from_status, to_status, planner_run_id, reason_code, event_id FROM control_transitions WHERE signal_id=? ORDER BY event_id").all(signalId).map((row) => ({ transitionId: String(row.transition_id), fromStatus: String(row.from_status), toStatus: String(row.to_status), plannerRunId: row.planner_run_id == null ? null : String(row.planner_run_id), reasonCode: String(row.reason_code), eventId: String(row.event_id) }));
    const edges = this.db.prepare("SELECT edge_id, edge_type, source_id, target_id, created_at, event_id FROM control_edges WHERE source_id=? OR target_id=? ORDER BY created_at, edge_id").all(signalId, signalId).map((row) => ({ edgeId: String(row.edge_id), edgeType: String(row.edge_type), sourceId: String(row.source_id), targetId: String(row.target_id), createdAt: String(row.created_at), eventId: String(row.event_id) }));
    const runIds = edges.filter((edge) => edge.edgeType === "signal_planner_run" && edge.sourceId === signalId).map((edge) => edge.targetId);
    const proposalIds = edges.filter((edge) => edge.edgeType === "signal_proposal" && edge.sourceId === signalId).map((edge) => edge.targetId);
    const plannerRuns = runIds.map((id) => this.db.prepare("SELECT planner_run_id, state, started_at, completed_at FROM control_planner_runs WHERE planner_run_id=?").get(id)).filter(Boolean).map((row) => ({ plannerRunId: String(row!.planner_run_id), state: String(row!.state), startedAt: String(row!.started_at), completedAt: row!.completed_at == null ? null : String(row!.completed_at) }));
    const proposals = proposalIds.map((id) => this.db.prepare("SELECT proposal_id, planner_run_id, ordinal, outcome, reason_code, task_id, EXISTS(SELECT 1 FROM tasks WHERE task_id=control_proposals.task_id) AS task_available FROM control_proposals WHERE proposal_id=?").get(id)).filter(Boolean).map((row) => ({ proposalId: String(row!.proposal_id), plannerRunId: String(row!.planner_run_id), ordinal: Number(row!.ordinal), outcome: String(row!.outcome), reasonCode: String(row!.reason_code), taskId: row!.task_id == null ? null : String(row!.task_id), taskAvailable: Boolean(row!.task_available) }));
    const fetchIds = [...new Set(observations.map((item) => item.fetchId))];
    const fetchEventIds = fetchIds.length ? this.db.prepare(`SELECT event_id FROM control_fetches WHERE fetch_id IN (${fetchIds.map(() => "?").join(",")})`).all(...fetchIds).map((row) => String(row.event_id)) : [];
    const eventIds = [String(signal.event_id), ...observations.map((row) => row.eventId), ...transitions.map((row) => row.eventId), ...edges.map((row) => row.eventId), ...fetchEventIds];
    return { signalId, provider: String(signal.provider), fingerprint: String(signal.fingerprint), status: String(signal.status), createdAt: String(signal.created_at), updatedAt: String(signal.updated_at), observations, transitions, plannerRuns, proposals, edges, eventCount: new Set(eventIds).size, revision: this.controlRevision() };
  }

  async readSignalEvents(signalId: string, cursor?: string | null, limit = 50) {
    const detail = this.getSignalDetail(signalId); if (!detail) return null;
    const decoded = cursor ? decodeCursor(cursor) : null;
    if (decoded && (decoded.scope !== "signal-events" || decoded.signalId !== signalId)) throw staleCursor("signal evidence cursor is stale");
    const ids = new Set<string>([...detail.observations.map((item) => item.eventId), ...detail.transitions.map((item) => item.eventId), ...detail.edges.map((item) => item.eventId)]);
    const fetchIds = [...new Set(detail.observations.map((item) => item.fetchId))];
    if (fetchIds.length) {
      const placeholders = fetchIds.map(() => "?").join(",");
      for (const row of this.db.prepare(`SELECT event_id FROM control_fetches WHERE fetch_id IN (${placeholders})`).all(...fetchIds)) ids.add(String(row.event_id));
    }
    ids.add(String(this.db.prepare("SELECT event_id FROM control_signals WHERE signal_id=?").get(signalId)?.event_id ?? ""));
    const records = this.db.prepare("SELECT event_id, relative_path, ordinal, sequence, byte_start, byte_end, occurred_at, kind FROM control_records ORDER BY sequence, event_id").all().filter((row) => ids.has(String(row.event_id)));
    const generation = [...new Set(records.map((row) => `${String(row.relative_path)}:${String(this.db.prepare("SELECT file_revision FROM control_files WHERE relative_path=?").get(String(row.relative_path))?.file_revision ?? "")}`))].sort().join("|");
    if (decoded && decoded.generation !== generation) throw staleCursor("signal evidence generation is stale");
    const start = decoded ? Number(decoded.index) : 0;
    if (!Number.isSafeInteger(start) || start < 0 || decoded && typeof decoded.generation !== "string") throw invalidCursor();
    const bounded = Math.min(100, Math.max(1, Math.floor(limit))); const page = records.slice(start, start + bounded);
    const values = [];
    const handles = new Map<string, Awaited<ReturnType<StewardArchiveRepository["acceptedControlFile"]>>>();
    try {
      for (const row of page) {
        const relativePath = String(row.relative_path);
        let accepted = handles.get(relativePath);
        if (!accepted) { accepted = await this.acceptedControlFile(relativePath); handles.set(relativePath, accepted); }
        const bytes = await readHandleRange(accepted.handle, Number(row.byte_start), Number(row.byte_end));
        if (bytes[bytes.length - 1] !== 10) throw staleCursor("control-loop event boundary changed");
        const event = validateControlEvent(parseCompleteJson(bytes.subarray(0, bytes.length - 1).toString("utf8"), relativePath));
        values.push({ eventId: String(row.event_id), sequence: Number(row.sequence), occurredAt: String(row.occurred_at), kind: String(row.kind), payload: event.payload });
      }
    } finally { for (const accepted of handles.values()) await accepted.handle.close(); }
    const nextIndex = start + page.length;
    const cursorValue = encodeCursor({ scope: "signal-events", signalId, generation, index: nextIndex });
    const nextCursor = nextIndex < records.length ? cursorValue : null;
    return { signalId, records: values, nextCursor, resumeCursor: cursorValue, hasMore: Boolean(nextCursor), revision: this.controlRevision() };
  }

  getPlannerRunDetail(plannerRunId: string) {
    if (!isSafeId(plannerRunId)) return null;
    const run = this.db.prepare("SELECT * FROM control_planner_runs WHERE planner_run_id=?").get(plannerRunId); if (!run) return null;
    const proposals = this.db.prepare("SELECT proposal_id, planner_run_id, ordinal, outcome, reason_code, signal_ids, dedupe_key, task_id, event_id, EXISTS(SELECT 1 FROM tasks WHERE task_id=control_proposals.task_id) AS task_available FROM control_proposals WHERE planner_run_id=? ORDER BY ordinal").all(plannerRunId).map((row) => ({ proposalId: String(row.proposal_id), plannerRunId: String(row.planner_run_id), ordinal: Number(row.ordinal), outcome: String(row.outcome), reasonCode: String(row.reason_code), signalIds: JSON.parse(String(row.signal_ids)) as string[], dedupeKey: row.dedupe_key == null ? null : String(row.dedupe_key), taskId: row.task_id == null ? null : String(row.task_id), taskAvailable: Boolean(row.task_available), eventId: String(row.event_id) }));
    const edges = this.db.prepare("SELECT edge_id, edge_type, source_id, target_id, created_at, event_id FROM control_edges WHERE source_id=? OR target_id=? ORDER BY created_at, edge_id").all(plannerRunId, plannerRunId).map((row) => ({ edgeId: String(row.edge_id), edgeType: String(row.edge_type), sourceId: String(row.source_id), targetId: String(row.target_id), createdAt: String(row.created_at), eventId: String(row.event_id) }));
    const artifacts = this.db.prepare("SELECT relative_path, media_type, availability, declared_size, declared_sha256, actual_size, status FROM control_artifacts WHERE planner_run_id=? ORDER BY relative_path").all(plannerRunId).map((row) => ({ path: String(row.relative_path), mediaType: row.media_type == null ? null : String(row.media_type), availability: String(row.availability), size: row.actual_size == null ? Number(row.declared_size) : Number(row.actual_size), sha256: String(row.declared_sha256), status: String(row.status) }));
    const wakeups = this.db.prepare("SELECT wakeup_id, reason, status, created_at, consumed_at, input_signal_ids, event_id FROM control_wakeups ORDER BY created_at DESC, wakeup_id DESC LIMIT 50").all().map((row) => ({ wakeupId: String(row.wakeup_id), reason: String(row.reason), status: String(row.status), createdAt: String(row.created_at), consumedAt: row.consumed_at == null ? null : String(row.consumed_at), inputSignalIds: JSON.parse(String(row.input_signal_ids)) as string[], eventId: String(row.event_id) }));
    const currentRow = this.db.prepare("SELECT generated_at, pending_signal_count, active_planner_run_id, status FROM control_current WHERE singleton=1").get();
    const current = currentRow ? { generatedAt: String(currentRow.generated_at), pendingSignalCount: currentRow.pending_signal_count == null ? null : Number(currentRow.pending_signal_count), activePlannerRunId: currentRow.active_planner_run_id == null ? null : String(currentRow.active_planner_run_id), status: String(currentRow.status) } : null;
    return { plannerRunId, state: String(run.state), epochId: String(run.epoch_id), startedAt: String(run.started_at), completedAt: run.completed_at == null ? null : String(run.completed_at), inputSignalIds: JSON.parse(String(run.input_signal_ids)) as string[], activeTaskIds: JSON.parse(String(run.active_task_ids)) as string[], wakeups, current, proposals, edges, artifacts, revision: this.controlRevision() };
  }

  getTaskProvenance(taskId: string) {
    if (!isSafeId(taskId)) return null;
    const rows = this.db.prepare("SELECT p.proposal_id, p.planner_run_id, p.outcome, p.reason_code FROM control_proposals p JOIN control_edges e ON e.edge_type='proposal_task' AND e.source_id=p.proposal_id AND e.target_id=? ORDER BY p.planner_run_id, p.ordinal").all(taskId);
    if (!rows.length) return null;
    const proposals = rows.map((row) => ({ proposalId: String(row.proposal_id), plannerRunId: String(row.planner_run_id), outcome: String(row.outcome), reasonCode: String(row.reason_code) }));
    const signals = this.db.prepare("SELECT DISTINCT e.source_id FROM control_edges e JOIN control_proposals p ON p.proposal_id=e.target_id JOIN control_edges pt ON pt.edge_type='proposal_task' AND pt.source_id=p.proposal_id AND pt.target_id=? WHERE e.edge_type='signal_proposal' ORDER BY e.source_id").all(taskId).map((row) => String(row.source_id));
    return { taskId, proposals, signals, revision: this.controlRevision() };
  }

  async readPlannerTranscript(plannerRunId: string, cursor?: string | null, limit = 50, artifactPath = "codex.jsonl") {
    const detail = this.getPlannerRunDetail(plannerRunId); if (!detail) return null;
    const artifact = detail.artifacts.find((item) => item.path === artifactPath); if (!artifact || artifact.status !== "verified") throw new Error("planner artifact is unavailable");
    const accepted = await this.acceptedControlArtifact(plannerRunId, artifactPath);
    try {
      const decoded = cursor ? decodeCursor(cursor) : null;
      if (decoded && (decoded.scope !== "planner-transcript" || decoded.plannerRunId !== plannerRunId || decoded.path !== artifactPath || decoded.fileRevision !== artifact.sha256)) throw staleCursor("planner transcript cursor is stale");
      const start = decoded ? Number(decoded.offset) : 0;
      const startOrdinal = decoded ? Number(decoded.ordinal) : 0;
      if (!Number.isSafeInteger(start) || start < 0 || start > accepted.size || !Number.isSafeInteger(startOrdinal) || startOrdinal < 0) throw invalidCursor();
      const bounded = Math.min(100, Math.max(1, Math.floor(limit)));
      const page = await readJsonlPage(accepted.handle, start, accepted.size, bounded);
      const records = page.records.map((value, index) => ({ ordinal: startOrdinal + index, value }));
      const nextOrdinal = startOrdinal + records.length;
      const cursorValue = encodeCursor({ scope: "planner-transcript", plannerRunId, path: artifactPath, fileRevision: artifact.sha256, offset: page.nextOffset, ordinal: nextOrdinal });
      return { plannerRunId, artifact: artifactPath, records, nextCursor: page.hasMore ? cursorValue : null, resumeCursor: cursorValue, hasMore: page.hasMore, revision: this.controlRevision(), incompleteTail: page.incompleteTail };
    } finally { await accepted.handle.close(); }
  }

  private async acceptedControlArtifact(plannerRunId: string, relativePath: string) {
    if (!isSafeId(plannerRunId) || !isSafeRelativePath(relativePath)) throw new Error("invalid planner artifact locator");
    const row = this.db.prepare("SELECT * FROM control_artifacts WHERE planner_run_id=? AND relative_path=? AND status='verified'").get(plannerRunId, relativePath);
    if (!row) throw new Error("planner artifact is unavailable");
    const resolved = await openControlArtifact(this.config.controlLoopRoot, `planner-runs/${plannerRunId}/${relativePath}`);
    const handle = await open(resolved.path, constants.O_RDONLY | constants.O_NOFOLLOW);
    try { const actual = await handle.stat(); if (!actual.isFile() || actual.size !== Number(row.declared_size) || await hashHandlePrefix(handle, actual.size) !== String(row.declared_sha256)) throw staleCursor("planner artifact identity changed"); return { handle, path: resolved.path, size: actual.size }; } catch (error) { await handle.close(); throw error; }
  }

  private async acceptedControlFile(relativePath: string) {
    if (!isSafeRelativePath(relativePath) || !relativePath.startsWith("events/")) throw new Error("invalid control-loop event locator");
    const file = this.db.prepare("SELECT * FROM control_files WHERE relative_path=? AND status='ready'").get(relativePath);
    if (!file) throw staleCursor("control-loop event generation is unavailable");
    const resolved = await openControlArtifact(this.config.controlLoopRoot, relativePath);
    const handle = await open(resolved.path, constants.O_RDONLY | constants.O_NOFOLLOW);
    try {
      const actual = await handle.stat();
      const acceptedEnd = Number(file.accepted_end);
      if (!actual.isFile() || actual.dev !== resolved.stat.dev || actual.ino !== resolved.stat.ino || String(actual.dev) !== String(file.device_id) || String(actual.ino) !== String(file.inode_id) || actual.size < acceptedEnd || await hashHandlePrefix(handle, acceptedEnd) !== String(file.prefix_hash)) throw staleCursor("control-loop event generation changed");
      return { handle, path: resolved.path, acceptedEnd, file };
    } catch (error) { await handle.close(); throw error; }
  }

  async readPlannerArtifact(plannerRunId: string, relativePath: string) {
    const accepted = await this.acceptedControlArtifact(plannerRunId, relativePath);
    const mediaType = String(this.db.prepare("SELECT media_type FROM control_artifacts WHERE planner_run_id=? AND relative_path=?").get(plannerRunId, relativePath)?.media_type ?? "application/octet-stream");
    const stream = accepted.size === 0 ? Readable.from([]) : accepted.handle.createReadStream({ start: 0, end: accepted.size - 1, autoClose: true });
    if (accepted.size === 0) await accepted.handle.close();
    return { stream, contentType: ["application/json", "application/x-ndjson", "text/plain", "text/markdown"].includes(mediaType) ? mediaType : "application/octet-stream", filename: basename(relativePath), size: accepted.size };
  }

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

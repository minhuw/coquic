import { createHash, randomUUID } from "node:crypto";
import { createReadStream } from "node:fs";
import { open, readdir, readFile, stat } from "node:fs/promises";
import type { DatabaseSync } from "node:sqlite";
import type { ArchiveConfig } from "./config";
import { readDatabaseMeta, withTransaction } from "./database";
import { assertDirectoryRoot, resolveDirectoryContainedPath, resolveRegularContainedPath } from "./paths";
import { isRecord, parseCompleteJson, safeInteger, validateControlCurrent, validateControlEpoch, validateControlEvent, validateControlManifest, type JsonRecord } from "./schema";

export type ControlLoopState = "indexing" | "ready" | "degraded" | "unavailable" | "incompatible" | "archive-corrupt";

export interface ControlLoopReconcileResult {
  changed: boolean;
  state: ControlLoopState;
  epochId: string | null;
  errorCategory: string | null;
  lastSuccessAt: string | null;
}

type EventRow = {
  eventId: string;
  epochId: string;
  sequence: number;
  occurredAt: string;
  kind: string;
  payload: JsonRecord;
  ordinal: number;
  byteStart: number;
  byteEnd: number;
};

type FileIdentity = {
  size: number;
  acceptedEnd: number;
  prefixHash: string;
  deviceId: string;
  inodeId: string;
  mtimeNs: string;
  ctimeNs: string;
};

const EVENT_PATH = /^events\/\d{4}\/\d{2}\/\d{2}\.jsonl$/;
const RUN_PATH = /^planner-runs\/([A-Za-z0-9][A-Za-z0-9_.:-]{0,127})$/;
const CONTROL_EVENT_KINDS = new Set([
  "signal_fetch.started", "signal_fetch.finished", "signal.created", "signal.observation",
  "signal.transition", "scheduler.wakeup", "daemon.cycle", "planner.started", "planner.finished",
  "planner.proposal", "graph.edge", "daemon.runtime",
]);

function now() { return new Date().toISOString(); }
function yieldToEventLoop() { return new Promise<void>((resolve) => setImmediate(resolve)); }
function json(value: unknown) { return JSON.stringify(value); }
function text(value: unknown) { return typeof value === "string" ? value : null; }
function int(value: unknown) { return typeof value === "number" && Number.isSafeInteger(value) ? value : null; }
function arrayFrom(value: unknown): string[] { return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : []; }
function mediaType(path: string) { if (path.endsWith(".jsonl")) return "application/x-ndjson"; if (path.endsWith(".json")) return "application/json"; if (path.endsWith(".md")) return "text/markdown"; if (path.endsWith(".log")) return "text/plain"; return "application/octet-stream"; }

async function acceptedEnd(path: string, size: number) {
  if (size === 0) return 0;
  const handle = await open(path, "r");
  try {
    const chunkSize = 64 * 1024;
    for (let end = size; end > 0;) {
      const start = Math.max(0, end - chunkSize);
      const buffer = Buffer.allocUnsafe(end - start);
      const { bytesRead } = await handle.read(buffer, 0, buffer.length, start);
      if (bytesRead !== buffer.length) throw new Error("control-loop event file changed while reading");
      const newline = buffer.lastIndexOf(10);
      if (newline >= 0) return start + newline + 1;
      end = start;
      await yieldToEventLoop();
    }
    return 0;
  } finally { await handle.close(); }
}

async function prefixHash(path: string, end: number) {
  const digest = createHash("sha256");
  if (end > 0) {
    for await (const chunk of createReadStream(path, { start: 0, end: end - 1, highWaterMark: 64 * 1024 })) {
      digest.update(chunk as Buffer);
      await yieldToEventLoop();
    }
  }
  return digest.digest("hex");
}

async function identity(path: string): Promise<FileIdentity> {
  const file = await stat(path, { bigint: true });
  const size = Number(file.size);
  const end = await acceptedEnd(path, size);
  return { size, acceptedEnd: end, prefixHash: await prefixHash(path, end), deviceId: String(file.dev), inodeId: String(file.ino), mtimeNs: String(file.mtimeNs), ctimeNs: String(file.ctimeNs) };
}

async function immutableIdentity(path: string): Promise<FileIdentity> {
  const file = await stat(path, { bigint: true });
  const size = Number(file.size);
  return { size, acceptedEnd: size, prefixHash: await prefixHash(path, size), deviceId: String(file.dev), inodeId: String(file.ino), mtimeNs: String(file.mtimeNs), ctimeNs: String(file.ctimeNs) };
}

async function listEventFiles(root: string, relative = "events"): Promise<string[]> {
  const directory = await resolveDirectoryContainedPath(root, relative);
  const entries = await readdir(directory, { withFileTypes: true });
  const files: string[] = [];
  for (const entry of entries) {
    if (entry.name.startsWith(".")) throw new Error("hidden control-loop entry");
    const path = `${relative}/${entry.name}`;
    if (entry.isSymbolicLink()) throw new Error("control-loop symlink");
    if (entry.isDirectory()) {
      if (!/^\d{4}$/.test(relative.split("/").at(-1) ?? "") && relative === "events" && !/^\d{4}$/.test(entry.name)) throw new Error("invalid event year");
      if (relative.split("/").length >= 4) throw new Error("invalid event directory");
      files.push(...await listEventFiles(root, path));
    } else if (entry.isFile() && EVENT_PATH.test(path)) files.push(path);
    else throw new Error("invalid control-loop event path");
  }
  return files.sort();
}

async function listRunFiles(root: string, runRelative: string): Promise<string[]> {
  const directory = await resolveDirectoryContainedPath(root, runRelative);
  const entries = await readdir(directory, { withFileTypes: true });
  const files: string[] = [];
  for (const entry of entries) {
    if (entry.name.startsWith(".")) throw new Error("hidden planner-run entry");
    const path = `${runRelative}/${entry.name}`;
    if (entry.isSymbolicLink()) throw new Error("planner-run symlink");
    if (entry.isDirectory()) throw new Error("planner-run nested directory");
    if (entry.isFile() && entry.name !== "manifest.json") files.push(path.slice(runRelative.length + 1));
    else if (!entry.isFile()) throw new Error("planner-run non-regular entry");
  }
  return files.sort();
}

async function scanEventBatches(path: string, end: number, startOffset: number, startOrdinal: number, expectedEpoch: string, batchSize: number, onBatch: (rows: EventRow[]) => void) {
  if (end <= startOffset) return 0;
  let lineFragments: Buffer[] = [];
  let lineStart = startOffset;
  let streamOffset = startOffset;
  let ordinal = startOrdinal;
  let batch: EventRow[] = [];
  for await (const value of createReadStream(path, { start: startOffset, end: end - 1, highWaterMark: 64 * 1024 })) {
    const chunk = value as Buffer;
    let position = 0;
    while (position < chunk.length) {
      const newline = chunk.indexOf(10, position);
      const segmentEnd = newline < 0 ? chunk.length : newline;
      lineFragments.push(chunk.subarray(position, segmentEnd));
      if (newline < 0) break;
      const event = validateControlEvent(parseCompleteJson(Buffer.concat(lineFragments).toString("utf8"), "control-loop event"));
      if (event.epochId !== expectedEpoch || !CONTROL_EVENT_KINDS.has(String(event.kind))) throw new Error("control-loop event identity mismatch");
      const sequence = safeInteger(event.sequence);
      if (sequence === null) throw new Error("control-loop event sequence is invalid");
      const byteEnd = streamOffset + newline + 1;
      batch.push({ eventId: String(event.eventId), epochId: String(event.epochId), sequence, occurredAt: String(event.occurredAt), kind: String(event.kind), payload: event.payload as JsonRecord, ordinal, byteStart: lineStart, byteEnd });
      ordinal += 1;
      lineStart = byteEnd;
      lineFragments = [];
      position = newline + 1;
      if (batch.length >= batchSize) { onBatch(batch); batch = []; await yieldToEventLoop(); }
    }
    streamOffset += chunk.length;
    await yieldToEventLoop();
  }
  if (lineFragments.length) throw new Error("control-loop accepted prefix is incomplete");
  if (batch.length) onBatch(batch);
  return ordinal - startOrdinal;
}

function normalizedMetadata(row: EventRow): JsonRecord {
  const payload = row.payload;
  if (row.kind === "signal_fetch.started" || row.kind === "signal_fetch.finished") {
    const fetch = isRecord(payload.fetch) ? payload.fetch : null;
    return fetch ? { fetchId: String(fetch.fetchId), provider: String(fetch.provider), status: String(fetch.status), startedAt: String(fetch.startedAt), completedAt: String(fetch.completedAt), itemCount: Number(fetch.itemCount), newItemCount: Number(fetch.newItemCount), hasMore: fetch.hasMore === true, error: text(fetch.error), summary: String(fetch.summary) } : {};
  } else if (row.kind === "signal.created") {
    const signal = isRecord(payload.signal) ? payload.signal : null;
    return signal ? { signalId: String(signal.signalId), provider: String(signal.provider), fingerprint: String(signal.fingerprint), status: String(signal.status), createdAt: String(signal.createdAt), updatedAt: String(signal.updatedAt), transition: text(signal.transition) } : {};
  } else if (row.kind === "signal.observation") {
    const observation = isRecord(payload.observation) ? payload.observation : null;
    return observation ? { observationId: String(observation.observationId), fetchId: String(observation.fetchId), provider: String(observation.provider), kind: String(observation.kind), fingerprint: String(observation.fingerprint), title: String(observation.title), summary: String(observation.summary), severity: text(observation.severity), canonicalSignalId: String(observation.canonicalSignalId), dedupeResult: String(observation.dedupeResult), observedAt: String(observation.observedAt) } : {};
  } else if (row.kind === "signal.transition") {
    const transition = isRecord(payload.transition) ? payload.transition : null;
    return transition ? { signalId: String(transition.signalId), fromStatus: String(transition.fromStatus), toStatus: String(transition.toStatus), plannerRunId: text(transition.plannerRunId), reasonCode: String(transition.reasonCode) } : {};
  } else if (row.kind === "scheduler.wakeup") {
    const wakeup = isRecord(payload.wakeup) ? payload.wakeup : null;
    return wakeup ? { wakeupId: String(wakeup.wakeupId), reason: String(wakeup.reason), status: String(wakeup.status), createdAt: String(wakeup.createdAt), consumedAt: text(wakeup.consumedAt), inputSignalIds: arrayFrom(wakeup.inputSignalIds) } : {};
  } else if (row.kind === "planner.started") {
    const planner = isRecord(payload.plannerRun) ? payload.plannerRun : null;
    return planner ? { plannerRunId: String(planner.plannerRunId), epochId: String(planner.epochId), state: String(planner.state), startedAt: String(planner.startedAt), completedAt: text(planner.completedAt), inputSignalIds: arrayFrom(planner.inputSignalIds), activeTaskIds: arrayFrom(planner.activeTaskIds) } : {};
  } else if (row.kind === "planner.finished") {
    return { plannerRunId: String(payload.plannerRunId), state: String(payload.state) };
  } else if (row.kind === "planner.proposal") {
    const proposal = isRecord(payload.proposal) ? payload.proposal : null;
    return proposal ? { proposalId: String(proposal.proposalId), plannerRunId: String(proposal.plannerRunId), ordinal: Number(proposal.ordinal), outcome: String(proposal.outcome), reasonCode: String(proposal.reasonCode), signalIds: arrayFrom(proposal.signalIds), dedupeKey: text(proposal.dedupeKey), taskId: text(proposal.taskId) } : {};
  } else if (row.kind === "graph.edge") {
    const edge = isRecord(payload.edge) ? payload.edge : null;
    return edge ? { edgeId: String(edge.edgeId), edgeType: String(edge.edgeType), sourceId: String(edge.sourceId), targetId: String(edge.targetId), createdAt: String(edge.createdAt) } : {};
  }
  return {};
}


function clearStaging(db: DatabaseSync, importToken: string) {
  db.prepare("DELETE FROM control_record_staging WHERE import_token=?").run(importToken);
  db.prepare("DELETE FROM control_normalized_staging WHERE import_token=?").run(importToken);
  db.prepare("DELETE FROM control_pending_link_staging WHERE import_token=?").run(importToken);
}

function stageEventBatch(db: DatabaseSync, importToken: string, relativePath: string, rows: EventRow[], excludedLivePath: string | null) {
  withTransaction(db, () => {
    for (const row of rows) {
      const conflict = excludedLivePath === null
        ? db.prepare("SELECT 1 FROM control_records WHERE event_id=? OR sequence=? LIMIT 1").get(row.eventId, row.sequence)
        : db.prepare("SELECT 1 FROM control_records WHERE relative_path != ? AND (event_id=? OR sequence=?) LIMIT 1").get(excludedLivePath, row.eventId, row.sequence);
      if (conflict) throw new Error("control-loop event identity conflict");
      db.prepare("INSERT INTO control_record_staging(import_token, event_id, relative_path, ordinal, sequence, byte_start, byte_end, occurred_at, kind) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)").run(importToken, row.eventId, relativePath, row.ordinal, row.sequence, row.byteStart, row.byteEnd, row.occurredAt, row.kind);
      db.prepare("INSERT INTO control_normalized_staging(import_token, event_id, sequence, occurred_at, kind, normalized_metadata) VALUES(?, ?, ?, ?, ?, ?)").run(importToken, row.eventId, row.sequence, row.occurredAt, row.kind, json(normalizedMetadata(row)));
    }
  });
}

function applyStagedNormalized(db: DatabaseSync, importToken: string) {
  db.prepare(`INSERT INTO control_fetches(fetch_id, provider, status, started_at, completed_at, item_count, new_item_count, has_more, error_reason, summary, event_id)
    SELECT json_extract(s.normalized_metadata, '$.fetchId'), json_extract(s.normalized_metadata, '$.provider'), json_extract(s.normalized_metadata, '$.status'), json_extract(s.normalized_metadata, '$.startedAt'), json_extract(s.normalized_metadata, '$.completedAt'), json_extract(s.normalized_metadata, '$.itemCount'), json_extract(s.normalized_metadata, '$.newItemCount'), json_extract(s.normalized_metadata, '$.hasMore'), json_extract(s.normalized_metadata, '$.error'), json_extract(s.normalized_metadata, '$.summary'), s.event_id
    FROM control_normalized_staging s WHERE s.import_token=? AND s.kind IN ('signal_fetch.started','signal_fetch.finished') AND s.sequence=(SELECT max(s2.sequence) FROM control_normalized_staging s2 WHERE s2.import_token=s.import_token AND s2.kind IN ('signal_fetch.started','signal_fetch.finished') AND json_extract(s2.normalized_metadata, '$.fetchId')=json_extract(s.normalized_metadata, '$.fetchId'))
    ON CONFLICT(fetch_id) DO UPDATE SET provider=excluded.provider,status=excluded.status,started_at=excluded.started_at,completed_at=excluded.completed_at,item_count=excluded.item_count,new_item_count=excluded.new_item_count,has_more=excluded.has_more,error_reason=excluded.error_reason,summary=excluded.summary,event_id=excluded.event_id`).run(importToken);
  db.prepare(`INSERT INTO control_signals(signal_id, provider, fingerprint, status, created_at, updated_at, transition_reason, event_id)
    SELECT json_extract(normalized_metadata, '$.signalId'), json_extract(normalized_metadata, '$.provider'), json_extract(normalized_metadata, '$.fingerprint'), json_extract(normalized_metadata, '$.status'), json_extract(normalized_metadata, '$.createdAt'), json_extract(normalized_metadata, '$.updatedAt'), json_extract(normalized_metadata, '$.transition'), event_id
    FROM control_normalized_staging WHERE import_token=? AND kind='signal.created'
    ON CONFLICT(signal_id) DO UPDATE SET provider=excluded.provider,fingerprint=excluded.fingerprint,status=excluded.status,created_at=excluded.created_at,updated_at=excluded.updated_at,transition_reason=excluded.transition_reason,event_id=excluded.event_id`).run(importToken);
  db.prepare(`INSERT INTO control_observations(observation_id, fetch_id, provider, kind, fingerprint, title, summary, severity, canonical_signal_id, dedupe_result, observed_at, event_id)
    SELECT json_extract(normalized_metadata, '$.observationId'), json_extract(normalized_metadata, '$.fetchId'), json_extract(normalized_metadata, '$.provider'), json_extract(normalized_metadata, '$.kind'), json_extract(normalized_metadata, '$.fingerprint'), json_extract(normalized_metadata, '$.title'), json_extract(normalized_metadata, '$.summary'), json_extract(normalized_metadata, '$.severity'), json_extract(normalized_metadata, '$.canonicalSignalId'), json_extract(normalized_metadata, '$.dedupeResult'), json_extract(normalized_metadata, '$.observedAt'), event_id
    FROM control_normalized_staging WHERE import_token=? AND kind='signal.observation'
    ON CONFLICT(observation_id) DO UPDATE SET fetch_id=excluded.fetch_id,provider=excluded.provider,kind=excluded.kind,fingerprint=excluded.fingerprint,title=excluded.title,summary=excluded.summary,severity=excluded.severity,canonical_signal_id=excluded.canonical_signal_id,dedupe_result=excluded.dedupe_result,observed_at=excluded.observed_at,event_id=excluded.event_id`).run(importToken);
  db.prepare(`INSERT INTO control_transitions(transition_id, signal_id, from_status, to_status, planner_run_id, reason_code, event_id)
    SELECT event_id, json_extract(normalized_metadata, '$.signalId'), json_extract(normalized_metadata, '$.fromStatus'), json_extract(normalized_metadata, '$.toStatus'), json_extract(normalized_metadata, '$.plannerRunId'), json_extract(normalized_metadata, '$.reasonCode'), event_id
    FROM control_normalized_staging WHERE import_token=? AND kind='signal.transition'
    ON CONFLICT(transition_id) DO UPDATE SET signal_id=excluded.signal_id,from_status=excluded.from_status,to_status=excluded.to_status,planner_run_id=excluded.planner_run_id,reason_code=excluded.reason_code,event_id=excluded.event_id`).run(importToken);
  db.prepare(`INSERT INTO control_wakeups(wakeup_id, reason, status, created_at, consumed_at, input_signal_ids, event_id)
    SELECT json_extract(normalized_metadata, '$.wakeupId'), json_extract(normalized_metadata, '$.reason'), json_extract(normalized_metadata, '$.status'), json_extract(normalized_metadata, '$.createdAt'), json_extract(normalized_metadata, '$.consumedAt'), json_extract(normalized_metadata, '$.inputSignalIds'), event_id
    FROM control_normalized_staging WHERE import_token=? AND kind='scheduler.wakeup'
    ON CONFLICT(wakeup_id) DO UPDATE SET reason=excluded.reason,status=excluded.status,created_at=excluded.created_at,consumed_at=excluded.consumed_at,input_signal_ids=excluded.input_signal_ids,event_id=excluded.event_id`).run(importToken);
  db.prepare(`INSERT INTO control_planner_runs(planner_run_id, epoch_id, state, started_at, completed_at, input_signal_ids, active_task_ids, started_event_id, finished_event_id)
    SELECT json_extract(normalized_metadata, '$.plannerRunId'), json_extract(normalized_metadata, '$.epochId'), json_extract(normalized_metadata, '$.state'), json_extract(normalized_metadata, '$.startedAt'), json_extract(normalized_metadata, '$.completedAt'), json_extract(normalized_metadata, '$.inputSignalIds'), json_extract(normalized_metadata, '$.activeTaskIds'), event_id, NULL
    FROM control_normalized_staging WHERE import_token=? AND kind='planner.started'
    ON CONFLICT(planner_run_id) DO UPDATE SET epoch_id=excluded.epoch_id,state=excluded.state,started_at=excluded.started_at,completed_at=excluded.completed_at,input_signal_ids=excluded.input_signal_ids,active_task_ids=excluded.active_task_ids,started_event_id=excluded.started_event_id`).run(importToken);
  db.prepare(`INSERT INTO control_proposals(proposal_id, planner_run_id, ordinal, outcome, reason_code, signal_ids, dedupe_key, task_id, event_id)
    SELECT json_extract(normalized_metadata, '$.proposalId'), json_extract(normalized_metadata, '$.plannerRunId'), json_extract(normalized_metadata, '$.ordinal'), json_extract(normalized_metadata, '$.outcome'), json_extract(normalized_metadata, '$.reasonCode'), json_extract(normalized_metadata, '$.signalIds'), json_extract(normalized_metadata, '$.dedupeKey'), json_extract(normalized_metadata, '$.taskId'), event_id
    FROM control_normalized_staging WHERE import_token=? AND kind='planner.proposal'
    ON CONFLICT(proposal_id) DO UPDATE SET planner_run_id=excluded.planner_run_id,ordinal=excluded.ordinal,outcome=excluded.outcome,reason_code=excluded.reason_code,signal_ids=excluded.signal_ids,dedupe_key=excluded.dedupe_key,task_id=excluded.task_id,event_id=excluded.event_id`).run(importToken);
  db.prepare(`INSERT INTO control_edges(edge_id, edge_type, source_id, target_id, created_at, event_id)
    SELECT json_extract(normalized_metadata, '$.edgeId'), json_extract(normalized_metadata, '$.edgeType'), json_extract(normalized_metadata, '$.sourceId'), json_extract(normalized_metadata, '$.targetId'), json_extract(normalized_metadata, '$.createdAt'), event_id
    FROM control_normalized_staging WHERE import_token=? AND kind='graph.edge'
    ON CONFLICT(edge_id) DO UPDATE SET edge_type=excluded.edge_type,source_id=excluded.source_id,target_id=excluded.target_id,created_at=excluded.created_at,event_id=excluded.event_id`).run(importToken);
  db.prepare(`UPDATE control_signals AS signal SET
    status=(SELECT json_extract(normalized_metadata, '$.toStatus') FROM control_normalized_staging WHERE import_token=? AND kind='signal.transition' AND json_extract(normalized_metadata, '$.signalId')=signal.signal_id ORDER BY sequence DESC LIMIT 1),
    transition_reason=(SELECT json_extract(normalized_metadata, '$.reasonCode') FROM control_normalized_staging WHERE import_token=? AND kind='signal.transition' AND json_extract(normalized_metadata, '$.signalId')=signal.signal_id ORDER BY sequence DESC LIMIT 1),
    updated_at=(SELECT occurred_at FROM control_normalized_staging WHERE import_token=? AND kind='signal.transition' AND json_extract(normalized_metadata, '$.signalId')=signal.signal_id ORDER BY sequence DESC LIMIT 1)
    WHERE EXISTS(SELECT 1 FROM control_normalized_staging WHERE import_token=? AND kind='signal.transition' AND json_extract(normalized_metadata, '$.signalId')=signal.signal_id)`).run(importToken, importToken, importToken, importToken);
  db.prepare(`UPDATE control_planner_runs AS run SET
    state=(SELECT json_extract(normalized_metadata, '$.state') FROM control_normalized_staging WHERE import_token=? AND kind='planner.finished' AND json_extract(normalized_metadata, '$.plannerRunId')=run.planner_run_id ORDER BY sequence DESC LIMIT 1),
    completed_at=(SELECT occurred_at FROM control_normalized_staging WHERE import_token=? AND kind='planner.finished' AND json_extract(normalized_metadata, '$.plannerRunId')=run.planner_run_id ORDER BY sequence DESC LIMIT 1),
    finished_event_id=(SELECT event_id FROM control_normalized_staging WHERE import_token=? AND kind='planner.finished' AND json_extract(normalized_metadata, '$.plannerRunId')=run.planner_run_id ORDER BY sequence DESC LIMIT 1)
    WHERE EXISTS(SELECT 1 FROM control_normalized_staging WHERE import_token=? AND kind='planner.finished' AND json_extract(normalized_metadata, '$.plannerRunId')=run.planner_run_id)`).run(importToken, importToken, importToken, importToken);
}

function replaceNormalizedGeneration(db: DatabaseSync, importToken: string) {
  db.exec("DELETE FROM control_edges; DELETE FROM control_transitions; DELETE FROM control_proposals; DELETE FROM control_observations; DELETE FROM control_signals; DELETE FROM control_wakeups; DELETE FROM control_fetches; DELETE FROM control_planner_runs WHERE started_event_id NOT LIKE 'manifest:%';");
  applyStagedNormalized(db, importToken);
}

async function stageNormalizedGeneration(db: DatabaseSync, root: string, epochId: string, sourceToken: string | null, excludedPath: string | null, batchSize: number) {
  const importToken = randomUUID();
  const recordsPage = excludedPath === null
    ? db.prepare("SELECT event_id, relative_path, ordinal, sequence, byte_start, byte_end, occurred_at, kind FROM control_records WHERE sequence > ? OR (sequence = ? AND event_id > ?) ORDER BY sequence, event_id LIMIT ?")
    : db.prepare("SELECT event_id, relative_path, ordinal, sequence, byte_start, byte_end, occurred_at, kind FROM control_records WHERE relative_path != ? AND (sequence > ? OR (sequence = ? AND event_id > ?)) ORDER BY sequence, event_id LIMIT ?");
  const sourcePage = sourceToken ? db.prepare("SELECT event_id, sequence, occurred_at, kind, normalized_metadata FROM control_normalized_staging WHERE import_token=? AND (sequence > ? OR (sequence = ? AND event_id > ?)) ORDER BY sequence, event_id LIMIT ?") : null;
  const insertNormalized = db.prepare("INSERT INTO control_normalized_staging(import_token, event_id, sequence, occurred_at, kind, normalized_metadata) VALUES(?, ?, ?, ?, ?, ?)");
  let handle: Awaited<ReturnType<typeof open>> | null = null;
  let handlePath: string | null = null;
  try {
    let staged: EventRow[] = [];
    const flush = () => {
      if (!staged.length) return;
      withTransaction(db, () => {
        for (const event of staged) insertNormalized.run(importToken, event.eventId, event.sequence, event.occurredAt, event.kind, json(normalizedMetadata(event)));
      });
      staged = [];
    };
    let afterSequence = -1;
    let afterEventId = "";
    while (true) {
      const records = excludedPath === null
        ? recordsPage.all(afterSequence, afterSequence, afterEventId, batchSize)
        : recordsPage.all(excludedPath, afterSequence, afterSequence, afterEventId, batchSize);
      if (!records.length) break;
      for (const record of records) {
        const relativePath = String(record.relative_path);
        if (!handle || handlePath !== relativePath) {
          if (handle) await handle.close();
          handle = null;
          handlePath = null;
          const file = db.prepare("SELECT accepted_end, prefix_hash, device_id, inode_id FROM control_files WHERE relative_path=? AND status='ready'").get(relativePath);
          if (!file) throw new Error("control-loop event file metadata is unavailable");
          const resolved = await resolveRegularContainedPath(root, relativePath);
          const end = Number(file.accepted_end);
          if (!Number.isSafeInteger(end) || end < 0 || resolved.stat.size < end || String(resolved.stat.dev) !== String(file.device_id) || String(resolved.stat.ino) !== String(file.inode_id) || await prefixHash(resolved.path, end) !== String(file.prefix_hash)) throw new Error("control-loop event file identity changed");
          handle = await open(resolved.path, "r");
          handlePath = relativePath;
        }
        const start = Number(record.byte_start); const end = Number(record.byte_end);
        if (!Number.isSafeInteger(start) || !Number.isSafeInteger(end) || start < 0 || end <= start) throw new Error("control-loop event range is invalid");
        const bytes = Buffer.allocUnsafe(end - start);
        const { bytesRead } = await handle.read(bytes, 0, bytes.length, start);
        if (bytesRead !== bytes.length || bytes.at(-1) !== 10) throw new Error("control-loop event range changed");
        const value = validateControlEvent(parseCompleteJson(bytes.subarray(0, bytes.length - 1).toString("utf8"), relativePath));
        if (value.eventId !== record.event_id || value.epochId !== epochId || value.sequence !== record.sequence || value.kind !== record.kind) throw new Error("control-loop event record changed");
        staged.push({ eventId: String(record.event_id), epochId, sequence: Number(record.sequence), occurredAt: String(record.occurred_at), kind: String(record.kind), payload: value.payload as JsonRecord, ordinal: Number(record.ordinal), byteStart: start, byteEnd: end });
      }
      flush();
      const last = records.at(-1)!;
      afterSequence = Number(last.sequence);
      afterEventId = String(last.event_id);
      await yieldToEventLoop();
    }
    if (sourceToken && sourcePage) {
      afterSequence = -1;
      afterEventId = "";
      while (true) {
        const rows = sourcePage.all(sourceToken, afterSequence, afterSequence, afterEventId, batchSize);
        if (!rows.length) break;
        withTransaction(db, () => {
          for (const row of rows) insertNormalized.run(importToken, row.event_id, row.sequence, row.occurred_at, row.kind, row.normalized_metadata);
        });
        const last = rows.at(-1)!;
        afterSequence = Number(last.sequence);
        afterEventId = String(last.event_id);
        await yieldToEventLoop();
      }
    }
    return importToken;
  } catch {
    clearStaging(db, importToken);
    throw new Error("control-loop normalized generation is invalid");
  } finally {
    if (handle) await handle.close();
  }
}

async function resolvePendingLinks(db: DatabaseSync, batchSize: number) {
  const importToken = randomUUID();
  let after = "";
  try {
    while (true) {
      const edges = db.prepare("SELECT edge_id, edge_type, source_id, target_id FROM control_edges WHERE edge_id > ? ORDER BY edge_id LIMIT ?").all(after, batchSize);
      if (!edges.length) break;
      withTransaction(db, () => {
        for (const edge of edges) {
          const exists = (id: string) => Boolean(db.prepare("SELECT 1 FROM control_signals WHERE signal_id=? UNION SELECT 1 FROM control_observations WHERE observation_id=? UNION SELECT 1 FROM control_planner_runs WHERE planner_run_id=? UNION SELECT 1 FROM control_proposals WHERE proposal_id=? UNION SELECT 1 FROM tasks WHERE task_id=? LIMIT 1").get(id, id, id, id, id));
          if (!exists(String(edge.source_id)) || !exists(String(edge.target_id))) db.prepare("INSERT INTO control_pending_link_staging(import_token, edge_id, source_id, target_id, edge_type, reason) VALUES(?, ?, ?, ?, ?, ?)").run(importToken, edge.edge_id, edge.source_id, edge.target_id, edge.edge_type, "endpoint-pending");
        }
      });
      after = String(edges.at(-1)!.edge_id);
      await yieldToEventLoop();
    }
    withTransaction(db, () => {
      db.exec("DELETE FROM control_pending_links");
      db.prepare("INSERT INTO control_pending_links(edge_id, source_id, target_id, edge_type, reason) SELECT edge_id, source_id, target_id, edge_type, reason FROM control_pending_link_staging WHERE import_token=? ORDER BY edge_id").run(importToken);
    });
  } finally { clearStaging(db, importToken); }
}

async function reconcileEvents(db: DatabaseSync, root: string, epochId: string, batchSize: number): Promise<{ changed: boolean; degraded: boolean }> {
  let files: string[];
  try { files = await listEventFiles(root); } catch (error) { if ((error as { code?: string }).code === "ENOENT") files = []; else return { changed: false, degraded: true }; }
  const seen = new Set(files);
  let changed = false;
  let degraded = false;
  for (const relativePath of files) {
    const resolved = await resolveRegularContainedPath(root, relativePath);
    const current = await identity(resolved.path);
    const incomplete = current.size > current.acceptedEnd;
    if (incomplete) degraded = true;
    const previous = db.prepare("SELECT * FROM control_files WHERE relative_path=?").get(relativePath);
    const sameFile = previous && String(previous.device_id) === current.deviceId && String(previous.inode_id) === current.inodeId;
    const previousEnd = Number(previous?.accepted_end ?? 0);
    const append = Boolean(sameFile && current.acceptedEnd >= previousEnd && previous?.prefix_hash === await prefixHash(resolved.path, previousEnd));
    if (previous && !append && incomplete) continue;
    const start = append ? previousEnd : 0;
    const startOrdinal = append ? Number(previous?.complete_records ?? 0) : 0;
    const importToken = randomUUID();
    let parsedRecords = 0;
    let priorSequence: number | null = null;
    try {
      parsedRecords = await scanEventBatches(resolved.path, current.acceptedEnd, start, startOrdinal, epochId, batchSize, (events) => {
        for (const event of events) {
          if (priorSequence !== null && event.sequence <= priorSequence) throw new Error("control-loop event sequence is not monotonic");
          priorSequence = event.sequence;
        }
        stageEventBatch(db, importToken, relativePath, events, append ? null : relativePath);
      });
    } catch {
      clearStaging(db, importToken);
      degraded = true;
      if (previous) db.prepare("UPDATE control_files SET status='ready', reason=? WHERE relative_path=?").run("event-invalid", relativePath);
      continue;
    }
    const otherMaximum = Number(db.prepare("SELECT max(sequence) AS sequence FROM control_records WHERE relative_path != ?").get(relativePath)?.sequence ?? -1);
    const stagedMinimum = db.prepare("SELECT min(sequence) AS sequence FROM control_record_staging WHERE import_token=?").get(importToken)?.sequence;
    const needsGeneration = Boolean(previous && !append) || stagedMinimum != null && Number(stagedMinimum) <= otherMaximum;
    let generationToken: string | null = null;
    if (needsGeneration) {
      try { generationToken = await stageNormalizedGeneration(db, root, epochId, importToken, append ? null : relativePath, batchSize); }
      catch {
        degraded = true;
        clearStaging(db, importToken);
        if (previous) db.prepare("UPDATE control_files SET status='ready', reason=? WHERE relative_path=?").run("event-generation-invalid", relativePath);
        continue;
      }
    }
    try {
      withTransaction(db, () => {
        if (!append) {
          db.prepare("DELETE FROM control_records WHERE relative_path=?").run(relativePath);
        }
        db.prepare(`INSERT INTO control_files(relative_path, kind, actual_size, accepted_end, prefix_hash, prefix_revision, complete_records, file_revision, device_id, inode_id, mtime_ns, ctime_ns, status, reason) VALUES(?, 'jsonl', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', NULL) ON CONFLICT(relative_path) DO UPDATE SET actual_size=excluded.actual_size,accepted_end=excluded.accepted_end,prefix_hash=excluded.prefix_hash,prefix_revision=excluded.prefix_revision,complete_records=excluded.complete_records,file_revision=excluded.file_revision,device_id=excluded.device_id,inode_id=excluded.inode_id,mtime_ns=excluded.mtime_ns,ctime_ns=excluded.ctime_ns,status='pending',reason=NULL`).run(relativePath, current.size, current.acceptedEnd, current.prefixHash, Number(previous?.prefix_revision ?? 0) + (append ? 0 : 1), startOrdinal + parsedRecords, append ? String(previous?.file_revision ?? `sha256:${current.prefixHash}`) : `sha256:${current.prefixHash}`, current.deviceId, current.inodeId, current.mtimeNs, current.ctimeNs);
        db.prepare("INSERT INTO control_records(event_id, relative_path, ordinal, sequence, byte_start, byte_end, occurred_at, kind) SELECT event_id, relative_path, ordinal, sequence, byte_start, byte_end, occurred_at, kind FROM control_record_staging WHERE import_token=? ORDER BY ordinal").run(importToken);
        if (generationToken) replaceNormalizedGeneration(db, generationToken);
        else applyStagedNormalized(db, importToken);
        db.prepare("UPDATE control_files SET status='ready', reason=NULL WHERE relative_path=?").run(relativePath);
      });
    } catch {
      degraded = true;
      clearStaging(db, importToken);
      if (generationToken) clearStaging(db, generationToken);
      if (previous) db.prepare("UPDATE control_files SET status='ready', reason=? WHERE relative_path=?").run("event-commit-conflict", relativePath);
      continue;
    }
    clearStaging(db, importToken);
    if (generationToken) clearStaging(db, generationToken);
    changed ||= parsedRecords > 0 || !previous || Number(previous.accepted_end) !== current.acceptedEnd || previous.prefix_hash !== current.prefixHash;
    await yieldToEventLoop();
  }
  const stale = db.prepare("SELECT relative_path FROM control_files WHERE relative_path LIKE 'events/%'").all().map((row) => String(row.relative_path)).filter((path) => !seen.has(path));
  for (const path of stale) {
    let generationToken: string;
    try { generationToken = await stageNormalizedGeneration(db, root, epochId, null, path, batchSize); }
    catch { degraded = true; continue; }
    try {
      withTransaction(db, () => {
        db.prepare("DELETE FROM control_records WHERE relative_path=?").run(path);
        db.prepare("DELETE FROM control_files WHERE relative_path=?").run(path);
        replaceNormalizedGeneration(db, generationToken);
      });
      changed = true;
    } finally { clearStaging(db, generationToken); }
  }
  return { changed, degraded };
}

async function reconcileCurrent(db: DatabaseSync, root: string, epochId: string) {
  let path: string;
  try {
    const resolved = await resolveRegularContainedPath(root, "current.json");
    path = resolved.path;
  } catch (error) {
    if ((error as { code?: string }).code === "ENOENT") return { changed: false, degraded: false };
    return { changed: false, degraded: true };
  }
  try {
    const value = validateControlCurrent(parseCompleteJson(await readFile(path, "utf8"), "current.json"));
    if (value.epochId !== epochId) throw new Error("current epoch mismatch");
    const counts = isRecord(value.counts) ? value.counts : {};
    const fileIdentity = await identity(path);
    const previous = db.prepare("SELECT file_revision, generated_at FROM control_current WHERE singleton=1").get();
    const revision = `sha256:${fileIdentity.prefixHash}`;
    const changed = previous?.file_revision !== revision || previous?.generated_at !== value.generatedAt;
    db.prepare(`INSERT INTO control_current(singleton, epoch_id, generated_at, fetch_count, observation_count, signal_count, planner_run_count, pending_signal_count, active_planner_run_id, status, file_revision) VALUES(1, ?, ?, ?, ?, ?, ?, ?, ?, 'ready', ?) ON CONFLICT(singleton) DO UPDATE SET epoch_id=excluded.epoch_id,generated_at=excluded.generated_at,fetch_count=excluded.fetch_count,observation_count=excluded.observation_count,signal_count=excluded.signal_count,planner_run_count=excluded.planner_run_count,pending_signal_count=excluded.pending_signal_count,active_planner_run_id=excluded.active_planner_run_id,status='ready',file_revision=excluded.file_revision`).run(epochId, String(value.generatedAt), int(counts.fetches), int(counts.observations), int(counts.signals), int(counts.plannerRuns), Array.isArray(value.pendingSignalIds) ? value.pendingSignalIds.length : null, text(value.activePlannerRunId), revision);
    return { changed, degraded: false };
  } catch { return { changed: false, degraded: true }; }
}

async function reconcileRuns(db: DatabaseSync, root: string, epochId: string): Promise<{ changed: boolean; corrupt: boolean; degraded: boolean }> {
  let directory;
  try { directory = await resolveDirectoryContainedPath(root, "planner-runs"); } catch { return { changed: false, corrupt: false, degraded: false }; }
  const entries = await readdir(directory, { withFileTypes: true });
  let changed = false;
  let corrupt = false;
  let degraded = false;
  const seen = new Set<string>();
  for (const entry of entries) {
    const relativePath = `planner-runs/${entry.name}`;
    if (entry.name.startsWith(".") || !entry.isDirectory() || !RUN_PATH.test(relativePath)) { degraded = true; continue; }
    seen.add(entry.name);
    const runId = entry.name;
    const manifestPath = `${relativePath}/manifest.json`;
    const retainedManifest = db.prepare("SELECT * FROM control_files WHERE relative_path=?").get(manifestPath);
    const prior = db.prepare("SELECT status FROM control_artifacts WHERE planner_run_id=? LIMIT 1").get(runId);
    const priorArtifacts = db.prepare("SELECT relative_path, declared_size, declared_sha256, status FROM control_artifacts WHERE planner_run_id=? ORDER BY relative_path").all(runId);
    const markCorrupt = () => {
      corrupt = true;
      const artifacts = db.prepare("UPDATE control_artifacts SET status='corrupt' WHERE planner_run_id=? AND status!='corrupt'").run(runId) as { changes: number | bigint };
      const manifest = retainedManifest ? db.prepare("UPDATE control_files SET status='corrupt', reason='immutable-manifest-conflict' WHERE relative_path=? AND status!='corrupt'").run(manifestPath) as { changes: number | bigint } : { changes: 0 };
      changed ||= Number(artifacts.changes) > 0 || Number(manifest.changes) > 0;
    };
    let manifest: JsonRecord;
    let manifestIdentity: FileIdentity;
    try {
      const resolved = await resolveRegularContainedPath(root, manifestPath);
      manifestIdentity = await immutableIdentity(resolved.path);
      if (retainedManifest && (Number(retainedManifest.actual_size) !== manifestIdentity.size || String(retainedManifest.prefix_hash) !== manifestIdentity.prefixHash)) { markCorrupt(); continue; }
      manifest = validateControlManifest(parseCompleteJson(await readFile(resolved.path, "utf8"), "planner manifest.json"));
    } catch { if (retainedManifest || prior?.status === "verified" || prior?.status === "corrupt") markCorrupt(); else degraded = true; continue; }
    if (manifest.epochId !== epochId || manifest.plannerRunId !== runId) { if (retainedManifest || prior?.status === "verified" || prior?.status === "corrupt") markCorrupt(); else degraded = true; continue; }
    let files: string[];
    try { files = await listRunFiles(root, relativePath); } catch { degraded = true; continue; }
    const declared = (manifest.files as JsonRecord[]).map((item) => String(item.path));
    if (declared.length !== files.length || declared.some((path, index) => path !== files[index])) { degraded = true; continue; }
    const verifiedArtifacts: Array<{ item: JsonRecord; identity: FileIdentity }> = [];
    let valid = true;
    for (const item of manifest.files as JsonRecord[]) {
      try {
        const resolved = await resolveRegularContainedPath(root, `${relativePath}/${String(item.path)}`);
        const artifactIdentity = await immutableIdentity(resolved.path);
        if (artifactIdentity.size !== Number(item.byteSize) || artifactIdentity.prefixHash !== String(item.sha256)) { valid = false; break; }
        verifiedArtifacts.push({ item, identity: artifactIdentity });
      } catch { valid = false; break; }
    }
    const artifactChanged = priorArtifacts.length !== (manifest.files as JsonRecord[]).length || (manifest.files as JsonRecord[]).some((item, index) => String(priorArtifacts[index]?.relative_path ?? "") !== String(item.path) || Number(priorArtifacts[index]?.declared_size ?? -1) !== Number(item.byteSize) || String(priorArtifacts[index]?.declared_sha256 ?? "") !== String(item.sha256) || String(priorArtifacts[index]?.status ?? "") !== "verified");
    if (!valid) {
      if (prior?.status === "verified" || prior?.status === "corrupt") corrupt = true;
      else degraded = true;
      if (prior) {
        const status = prior.status === "verified" || prior.status === "corrupt" ? "corrupt" : "pending";
        db.prepare("UPDATE control_artifacts SET status=? WHERE planner_run_id=?").run(status, runId);
        changed ||= String(prior.status) !== status;
      }
      continue;
    }
    withTransaction(db, () => {
      db.prepare(`INSERT INTO control_files(relative_path, kind, actual_size, accepted_end, prefix_hash, prefix_revision, complete_records, file_revision, device_id, inode_id, mtime_ns, ctime_ns, status, reason) VALUES(?, 'manifest', ?, ?, ?, 1, 1, ?, ?, ?, ?, ?, 'ready', NULL) ON CONFLICT(relative_path) DO UPDATE SET status='ready',reason=NULL`).run(manifestPath, manifestIdentity.size, manifestIdentity.acceptedEnd, manifestIdentity.prefixHash, `sha256:${manifestIdentity.prefixHash}`, manifestIdentity.deviceId, manifestIdentity.inodeId, manifestIdentity.mtimeNs, manifestIdentity.ctimeNs);
      db.prepare("DELETE FROM control_artifacts WHERE planner_run_id=?").run(runId);
      for (const artifact of verifiedArtifacts) db.prepare("INSERT INTO control_artifacts(planner_run_id, relative_path, media_type, availability, declared_size, declared_sha256, actual_size, device_id, inode_id, mtime_ns, ctime_ns, status) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'verified')").run(runId, String(artifact.item.path), mediaType(String(artifact.item.path)), String(artifact.item.availability), Number(artifact.item.byteSize), String(artifact.item.sha256), artifact.identity.size, artifact.identity.deviceId, artifact.identity.inodeId, artifact.identity.mtimeNs, artifact.identity.ctimeNs);
      db.prepare("UPDATE control_planner_runs SET state=?, completed_at=coalesce(completed_at, ?), epoch_id=? WHERE planner_run_id=?").run(String(manifest.terminalState), String(manifest.completedAt), epochId, runId);
      if (!db.prepare("SELECT 1 FROM control_planner_runs WHERE planner_run_id=?").get(runId)) db.prepare("INSERT INTO control_planner_runs(planner_run_id, epoch_id, state, started_at, completed_at, input_signal_ids, active_task_ids, started_event_id, finished_event_id) VALUES(?, ?, ?, ?, ?, '[]', '[]', ?, NULL)").run(runId, epochId, String(manifest.terminalState), String(manifest.completedAt), String(manifest.completedAt), `manifest:${runId}`);
    });
    changed ||= artifactChanged || !prior || !retainedManifest;
  }
  return { changed, corrupt, degraded };
}

function domainStatus(db: DatabaseSync) {
  return db.prepare("SELECT state, epoch_id, last_error_category, last_success_at FROM domain_health WHERE domain='control-loop'").get();
}

function domainHealthChanged(previous: ReturnType<typeof domainStatus>, state: ControlLoopState, epochId: string | null, errorCategory: string | null) {
  return !previous || String(previous.state) !== state || (previous.epoch_id == null ? null : String(previous.epoch_id)) !== epochId || (previous.last_error_category == null ? null : String(previous.last_error_category)) !== errorCategory;
}

export async function reconcileControlLoop(db: DatabaseSync, config: ArchiveConfig): Promise<ControlLoopReconcileResult> {
  const attemptedAt = now();
  const prior = domainStatus(db);
  const retainedEpochId = prior?.epoch_id == null ? null : String(prior.epoch_id);
  const retainedSuccessAt = prior?.last_success_at == null ? null : String(prior.last_success_at);
  if (!config.controlLoopRoot) {
    db.prepare(`INSERT INTO domain_health(domain, state, last_attempt_at, last_error_category, last_error_count) VALUES('control-loop', 'unavailable', ?, 'root-unconfigured', 1) ON CONFLICT(domain) DO UPDATE SET state='unavailable',last_attempt_at=excluded.last_attempt_at,last_error_category=excluded.last_error_category,last_error_count=1`).run(attemptedAt);
    return { changed: domainHealthChanged(prior, "unavailable", retainedEpochId, "root-unconfigured"), state: "unavailable", epochId: retainedEpochId, errorCategory: "root-unconfigured", lastSuccessAt: retainedSuccessAt };
  }
  try {
    await assertDirectoryRoot(config.controlLoopRoot);
  } catch {
    db.prepare(`INSERT INTO domain_health(domain, state, last_attempt_at, last_error_category, last_error_count) VALUES('control-loop', 'unavailable', ?, 'root-unavailable', 1) ON CONFLICT(domain) DO UPDATE SET state='unavailable',last_attempt_at=excluded.last_attempt_at,last_error_category=excluded.last_error_category,last_error_count=1`).run(attemptedAt);
    return { changed: domainHealthChanged(prior, "unavailable", retainedEpochId, "root-unavailable"), state: "unavailable", epochId: retainedEpochId, errorCategory: "root-unavailable", lastSuccessAt: retainedSuccessAt };
  }
  let epoch: ReturnType<typeof validateControlEpoch>;
  try { epoch = validateControlEpoch(parseCompleteJson(await readFile((await resolveRegularContainedPath(config.controlLoopRoot, "epoch.json")).path, "utf8"), "control-loop epoch.json")); }
  catch {
    db.prepare(`INSERT INTO domain_health(domain, state, last_attempt_at, last_error_category, last_error_count) VALUES('control-loop', 'degraded', ?, 'epoch-invalid', 1) ON CONFLICT(domain) DO UPDATE SET state='degraded',last_attempt_at=excluded.last_attempt_at,last_error_category=excluded.last_error_category,last_error_count=1`).run(attemptedAt);
    return { changed: domainHealthChanged(prior, "degraded", retainedEpochId, "epoch-invalid"), state: "degraded", epochId: retainedEpochId, errorCategory: "epoch-invalid", lastSuccessAt: retainedSuccessAt };
  }
  const taskEpoch = readDatabaseMeta(db).epochId;
  if ((prior?.epoch_id && String(prior.epoch_id) !== epoch.epochId) || (taskEpoch && taskEpoch !== epoch.epochId)) {
    db.prepare(`INSERT INTO domain_health(domain, state, epoch_id, last_attempt_at, last_error_category, last_error_count) VALUES('control-loop', 'incompatible', ?, ?, 'epoch-mismatch', 1) ON CONFLICT(domain) DO UPDATE SET state='incompatible',epoch_id=excluded.epoch_id,last_attempt_at=excluded.last_attempt_at,last_error_category=excluded.last_error_category,last_error_count=1`).run(epoch.epochId, attemptedAt);
    return { changed: domainHealthChanged(prior, "incompatible", epoch.epochId, "epoch-mismatch"), state: "incompatible", epochId: epoch.epochId, errorCategory: "epoch-mismatch", lastSuccessAt: null };
  }
  db.prepare(`INSERT INTO domain_health(domain, state, epoch_id, last_attempt_at, last_error_category, last_error_count) VALUES('control-loop', 'indexing', ?, ?, NULL, 0) ON CONFLICT(domain) DO UPDATE SET state='indexing',epoch_id=excluded.epoch_id,last_attempt_at=excluded.last_attempt_at,last_error_category=NULL,last_error_count=0`).run(epoch.epochId, attemptedAt);
  const eventResult = await reconcileEvents(db, config.controlLoopRoot, epoch.epochId, config.batchSize);
  const currentResult = await reconcileCurrent(db, config.controlLoopRoot, epoch.epochId);
  const runResult = await reconcileRuns(db, config.controlLoopRoot, epoch.epochId);
  await resolvePendingLinks(db, config.batchSize);
  const state: ControlLoopState = runResult.corrupt ? "archive-corrupt" : eventResult.degraded || currentResult.degraded || runResult.degraded ? "degraded" : "ready";
  const errorCategory = state === "ready" ? null : runResult.corrupt ? "archive-corrupt" : "control-loop-pending";
  const changed = eventResult.changed || currentResult.changed || runResult.changed || domainHealthChanged(prior, state, epoch.epochId, errorCategory);
  const succeededAt = now();
  db.prepare(`UPDATE domain_health SET state=?, root_revision=?, last_success_at=?, last_error_category=?, last_error_count=?, lag_seconds=0 WHERE domain='control-loop'`).run(state, `epoch:${epoch.epochId}`, succeededAt, errorCategory, state === "ready" ? 0 : 1);
  return { changed, state, epochId: epoch.epochId, errorCategory, lastSuccessAt: succeededAt };
}

export async function readControlEventRecord(root: string, relativePath: string, start: number, end: number) {
  const resolved = await resolveRegularContainedPath(root, relativePath);
  if (start < 0 || end <= start || end > resolved.stat.size) throw new Error("control-loop event cursor is stale");
  const handle = await open(resolved.path, "r");
  try {
    const bytes = Buffer.allocUnsafe(end - start);
    const { bytesRead } = await handle.read(bytes, 0, bytes.length, start);
    if (bytesRead !== bytes.length || bytes.at(-1) !== 10) throw new Error("control-loop event cursor is stale");
    return validateControlEvent(parseCompleteJson(bytes.subarray(0, bytes.length - 1).toString("utf8"), relativePath));
  } finally { await handle.close(); }
}

export async function openControlArtifact(root: string, relativePath: string) {
  return resolveRegularContainedPath(root, relativePath);
}

import { createHash } from "node:crypto";
import { readdir, readFile, stat } from "node:fs/promises";
import type { DatabaseSync } from "node:sqlite";
import type { ArchiveConfig } from "./config";
import { readDatabaseMeta, withTransaction } from "./database";
import { assertDirectoryRoot, resolveDirectoryContainedPath, resolveRegularContainedPath } from "./paths";
import { isRecord, parseCompleteJson, safeInteger, safeString, validateControlCurrent, validateControlEpoch, validateControlEvent, validateControlManifest, type JsonRecord } from "./schema";

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
function arrayIds(value: unknown) { return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string").join("\u001f") : ""; }
function arrayFrom(value: unknown): string[] { return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : []; }
function mediaType(path: string) { if (path.endsWith(".jsonl")) return "application/x-ndjson"; if (path.endsWith(".json")) return "application/json"; if (path.endsWith(".md")) return "text/markdown"; if (path.endsWith(".log")) return "text/plain"; return "application/octet-stream"; }

async function acceptedEnd(path: string, size: number) {
  if (size === 0) return 0;
  const bytes = await readFile(path);
  const newline = bytes.lastIndexOf(10);
  return newline < 0 ? 0 : newline + 1;
}

async function prefixHash(path: string, end: number) {
  const digest = createHash("sha256");
  if (end > 0) digest.update((await readFile(path)).subarray(0, end));
  return digest.digest("hex");
}

async function identity(path: string): Promise<FileIdentity> {
  const file = await stat(path, { bigint: true });
  const size = Number(file.size);
  const end = await acceptedEnd(path, size);
  return { size, acceptedEnd: end, prefixHash: await prefixHash(path, end), deviceId: String(file.dev), inodeId: String(file.ino), mtimeNs: String(file.mtimeNs), ctimeNs: String(file.ctimeNs) };
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

async function parseEvents(path: string, end: number, startOffset: number, startOrdinal: number, expectedEpoch: string): Promise<EventRow[]> {
  if (end <= startOffset) return [];
  const source = (await readFile(path)).subarray(startOffset, end);
  const rows: EventRow[] = [];
  let lineStart = startOffset;
  let position = 0;
  let ordinal = startOrdinal;
  while (position < source.length) {
    const newline = source.indexOf(10, position);
    if (newline < 0) break;
    const line = source.subarray(position, newline).toString("utf8");
    const value = validateControlEvent(parseCompleteJson(line, "control-loop event"));
    if (value.epochId !== expectedEpoch || !CONTROL_EVENT_KINDS.has(String(value.kind))) throw new Error("control-loop event identity mismatch");
    const sequence = safeInteger(value.sequence);
    if (sequence === null) throw new Error("control-loop event sequence is invalid");
    rows.push({ eventId: String(value.eventId), epochId: String(value.epochId), sequence, occurredAt: String(value.occurredAt), kind: String(value.kind), payload: value.payload as JsonRecord, ordinal, byteStart: lineStart, byteEnd: startOffset + newline + 1 });
    ordinal += 1;
    lineStart = startOffset + newline + 1;
    position = newline + 1;
  }
  return rows;
}

function deleteEventData(db: DatabaseSync, eventIds: string[]) {
  if (!eventIds.length) return;
  const statements = [
    "DELETE FROM control_edges WHERE event_id=?", "DELETE FROM control_transitions WHERE event_id=?",
    "DELETE FROM control_proposals WHERE event_id=?", "DELETE FROM control_observations WHERE event_id=?",
    "DELETE FROM control_signals WHERE event_id=?", "DELETE FROM control_wakeups WHERE event_id=?",
    "DELETE FROM control_fetches WHERE event_id=?", "DELETE FROM control_planner_runs WHERE started_event_id=? OR finished_event_id=?",
  ];
  for (const eventId of eventIds) {
    for (const statement of statements) {
      if (statement.includes("OR")) db.prepare(statement).run(eventId, eventId);
      else db.prepare(statement).run(eventId);
    }
  }
}

function normalizeEvent(db: DatabaseSync, row: EventRow) {
  const payload = row.payload;
  if (row.kind === "signal_fetch.started" || row.kind === "signal_fetch.finished") {
    const fetch = isRecord(payload.fetch) ? payload.fetch : null;
    if (!fetch) return;
    db.prepare(`INSERT INTO control_fetches(fetch_id, provider, status, started_at, completed_at, item_count, new_item_count, has_more, error_reason, summary, event_id) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(fetch_id) DO UPDATE SET provider=excluded.provider,status=excluded.status,started_at=excluded.started_at,completed_at=excluded.completed_at,item_count=excluded.item_count,new_item_count=excluded.new_item_count,has_more=excluded.has_more,error_reason=excluded.error_reason,summary=excluded.summary,event_id=excluded.event_id`).run(String(fetch.fetchId), String(fetch.provider), String(fetch.status), String(fetch.startedAt), String(fetch.completedAt), Number(fetch.itemCount), Number(fetch.newItemCount), fetch.hasMore ? 1 : 0, text(fetch.error), String(fetch.summary), row.eventId);
  } else if (row.kind === "signal.created") {
    const signal = isRecord(payload.signal) ? payload.signal : null;
    if (!signal) return;
    db.prepare(`INSERT INTO control_signals(signal_id, provider, fingerprint, status, created_at, updated_at, transition_reason, event_id) VALUES(?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(signal_id) DO UPDATE SET provider=excluded.provider,fingerprint=excluded.fingerprint,status=excluded.status,created_at=excluded.created_at,updated_at=excluded.updated_at,transition_reason=excluded.transition_reason,event_id=excluded.event_id`).run(String(signal.signalId), String(signal.provider), String(signal.fingerprint), String(signal.status), String(signal.createdAt), String(signal.updatedAt), text(signal.transition), row.eventId);
  } else if (row.kind === "signal.observation") {
    const observation = isRecord(payload.observation) ? payload.observation : null;
    if (!observation) return;
    db.prepare(`INSERT INTO control_observations(observation_id, fetch_id, provider, kind, fingerprint, title, summary, severity, canonical_signal_id, dedupe_result, observed_at, event_id) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(observation_id) DO UPDATE SET fetch_id=excluded.fetch_id,provider=excluded.provider,kind=excluded.kind,fingerprint=excluded.fingerprint,title=excluded.title,summary=excluded.summary,severity=excluded.severity,canonical_signal_id=excluded.canonical_signal_id,dedupe_result=excluded.dedupe_result,observed_at=excluded.observed_at,event_id=excluded.event_id`).run(String(observation.observationId), String(observation.fetchId), String(observation.provider), String(observation.kind), String(observation.fingerprint), String(observation.title), String(observation.summary), text(observation.severity), String(observation.canonicalSignalId), String(observation.dedupeResult), String(observation.observedAt), row.eventId);
  } else if (row.kind === "signal.transition") {
    const transition = isRecord(payload.transition) ? payload.transition : null;
    if (!transition) return;
    db.prepare(`INSERT INTO control_transitions(transition_id, signal_id, from_status, to_status, planner_run_id, reason_code, event_id) VALUES(?, ?, ?, ?, ?, ?, ?) ON CONFLICT(transition_id) DO UPDATE SET signal_id=excluded.signal_id,from_status=excluded.from_status,to_status=excluded.to_status,planner_run_id=excluded.planner_run_id,reason_code=excluded.reason_code,event_id=excluded.event_id`).run(row.eventId, String(transition.signalId), String(transition.fromStatus), String(transition.toStatus), text(transition.plannerRunId), String(transition.reasonCode), row.eventId);
    db.prepare("UPDATE control_signals SET status=?, transition_reason=?, updated_at=? WHERE signal_id=?").run(String(transition.toStatus), String(transition.reasonCode), row.occurredAt, String(transition.signalId));
  } else if (row.kind === "scheduler.wakeup") {
    const wakeup = isRecord(payload.wakeup) ? payload.wakeup : null;
    if (!wakeup) return;
    db.prepare(`INSERT INTO control_wakeups(wakeup_id, reason, status, created_at, consumed_at, input_signal_ids, event_id) VALUES(?, ?, ?, ?, ?, ?, ?) ON CONFLICT(wakeup_id) DO UPDATE SET reason=excluded.reason,status=excluded.status,created_at=excluded.created_at,consumed_at=excluded.consumed_at,input_signal_ids=excluded.input_signal_ids,event_id=excluded.event_id`).run(String(wakeup.wakeupId), String(wakeup.reason), String(wakeup.status), String(wakeup.createdAt), text(wakeup.consumedAt), json(arrayFrom(wakeup.inputSignalIds)), row.eventId);
  } else if (row.kind === "planner.started") {
    const planner = isRecord(payload.plannerRun) ? payload.plannerRun : null;
    if (!planner) return;
    db.prepare(`INSERT INTO control_planner_runs(planner_run_id, epoch_id, state, started_at, completed_at, input_signal_ids, active_task_ids, started_event_id, finished_event_id) VALUES(?, ?, ?, ?, ?, ?, ?, ?, NULL) ON CONFLICT(planner_run_id) DO UPDATE SET epoch_id=excluded.epoch_id,state=excluded.state,started_at=excluded.started_at,completed_at=excluded.completed_at,input_signal_ids=excluded.input_signal_ids,active_task_ids=excluded.active_task_ids,started_event_id=excluded.started_event_id`).run(String(planner.plannerRunId), String(planner.epochId), String(planner.state), String(planner.startedAt), text(planner.completedAt), json(arrayFrom(planner.inputSignalIds)), json(arrayFrom(planner.activeTaskIds)), row.eventId);
  } else if (row.kind === "planner.finished") {
    db.prepare("UPDATE control_planner_runs SET state=?, completed_at=?, finished_event_id=? WHERE planner_run_id=?").run(String(payload.state), row.occurredAt, row.eventId, String(payload.plannerRunId));
  } else if (row.kind === "planner.proposal") {
    const proposal = isRecord(payload.proposal) ? payload.proposal : null;
    if (!proposal) return;
    db.prepare(`INSERT INTO control_proposals(proposal_id, planner_run_id, ordinal, outcome, reason_code, signal_ids, dedupe_key, task_id, event_id) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(proposal_id) DO UPDATE SET planner_run_id=excluded.planner_run_id,ordinal=excluded.ordinal,outcome=excluded.outcome,reason_code=excluded.reason_code,signal_ids=excluded.signal_ids,dedupe_key=excluded.dedupe_key,task_id=excluded.task_id,event_id=excluded.event_id`).run(String(proposal.proposalId), String(proposal.plannerRunId), Number(proposal.ordinal), String(proposal.outcome), String(proposal.reasonCode), json(arrayFrom(proposal.signalIds)), text(proposal.dedupeKey), text(proposal.taskId), row.eventId);
  } else if (row.kind === "graph.edge") {
    const edge = isRecord(payload.edge) ? payload.edge : null;
    if (!edge) return;
    db.prepare(`INSERT INTO control_edges(edge_id, edge_type, source_id, target_id, created_at, event_id) VALUES(?, ?, ?, ?, ?, ?) ON CONFLICT(edge_id) DO UPDATE SET edge_type=excluded.edge_type,source_id=excluded.source_id,target_id=excluded.target_id,created_at=excluded.created_at,event_id=excluded.event_id`).run(String(edge.edgeId), String(edge.edgeType), String(edge.sourceId), String(edge.targetId), String(edge.createdAt), row.eventId);
  }
}

function resolvePendingLinks(db: DatabaseSync) {
  db.exec("DELETE FROM control_pending_links");
  const edges = db.prepare("SELECT edge_id, edge_type, source_id, target_id FROM control_edges").all();
  for (const edge of edges) {
    const exists = (id: string) => Boolean(db.prepare("SELECT 1 FROM control_signals WHERE signal_id=? UNION SELECT 1 FROM control_observations WHERE observation_id=? UNION SELECT 1 FROM control_planner_runs WHERE planner_run_id=? UNION SELECT 1 FROM control_proposals WHERE proposal_id=? UNION SELECT 1 FROM tasks WHERE task_id=? LIMIT 1").get(id, id, id, id, id));
    if (!exists(String(edge.source_id)) || !exists(String(edge.target_id))) db.prepare("INSERT INTO control_pending_links(edge_id, source_id, target_id, edge_type, reason) VALUES(?, ?, ?, ?, ?)").run(edge.edge_id, edge.source_id, edge.target_id, edge.edge_type, "endpoint-pending");
  }
}

async function reconcileEvents(db: DatabaseSync, root: string, epochId: string): Promise<{ changed: boolean; degraded: boolean }> {
  let files: string[];
  try { files = await listEventFiles(root); } catch (error) { if ((error as { code?: string }).code === "ENOENT") files = []; else return { changed: false, degraded: true }; }
  const seen = new Set(files);
  let changed = false;
  let degraded = false;
  for (const relativePath of files) {
    const resolved = await resolveRegularContainedPath(root, relativePath);
    const current = await identity(resolved.path);
    if (current.size > current.acceptedEnd) degraded = true;
    const previous = db.prepare("SELECT * FROM control_files WHERE relative_path=?").get(relativePath);
    const sameFile = previous && String(previous.device_id) === current.deviceId && String(previous.inode_id) === current.inodeId;
    const previousEnd = Number(previous?.accepted_end ?? 0);
    const append = Boolean(sameFile && current.acceptedEnd >= previousEnd && previous?.prefix_hash === await prefixHash(resolved.path, previousEnd));
    const start = append ? previousEnd : 0;
    const startOrdinal = append ? Number(previous?.complete_records ?? 0) : 0;
    let events: EventRow[];
    try { events = await parseEvents(resolved.path, current.acceptedEnd, start, startOrdinal, epochId); }
    catch {
      degraded = true;
      if (previous) db.prepare("UPDATE control_files SET status='ready', reason=? WHERE relative_path=?").run("event-invalid", relativePath);
      continue;
    }
    const allSequences = db.prepare("SELECT sequence FROM control_records WHERE relative_path != ?").all(relativePath).map((row) => Number(row.sequence));
    const sequenceSet = new Set(allSequences);
    let valid = true;
    let priorSequence: number | null = null;
    for (const event of events) {
      if (sequenceSet.has(event.sequence) || priorSequence !== null && event.sequence <= priorSequence) { valid = false; break; }
      sequenceSet.add(event.sequence);
      priorSequence = event.sequence;
    }
    if (!valid) {
      degraded = true;
      if (previous) db.prepare("UPDATE control_files SET status='ready', reason=? WHERE relative_path=?").run("event-sequence-conflict", relativePath);
      continue;
    }
    const oldIds = append ? [] : db.prepare("SELECT event_id FROM control_records WHERE relative_path=?").all(relativePath).map((row) => String(row.event_id));
    withTransaction(db, () => {
      if (!append) {
        deleteEventData(db, oldIds);
        db.prepare("DELETE FROM control_records WHERE relative_path=?").run(relativePath);
      }
      db.prepare(`INSERT INTO control_files(relative_path, kind, actual_size, accepted_end, prefix_hash, prefix_revision, complete_records, file_revision, device_id, inode_id, mtime_ns, ctime_ns, status, reason) VALUES(?, 'jsonl', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', NULL) ON CONFLICT(relative_path) DO UPDATE SET actual_size=excluded.actual_size,accepted_end=excluded.accepted_end,prefix_hash=excluded.prefix_hash,prefix_revision=excluded.prefix_revision,complete_records=excluded.complete_records,file_revision=excluded.file_revision,device_id=excluded.device_id,inode_id=excluded.inode_id,mtime_ns=excluded.mtime_ns,ctime_ns=excluded.ctime_ns,status='pending',reason=NULL`).run(relativePath, current.size, current.acceptedEnd, current.prefixHash, Number(previous?.prefix_revision ?? 0) + (append ? 0 : 1), Number(previous?.complete_records ?? 0) + events.length, append ? String(previous?.file_revision ?? `sha256:${current.prefixHash}`) : `sha256:${current.prefixHash}`, current.deviceId, current.inodeId, current.mtimeNs, current.ctimeNs);
      for (const event of events) {
        db.prepare("INSERT OR REPLACE INTO control_records(event_id, relative_path, ordinal, sequence, byte_start, byte_end, occurred_at, kind) VALUES(?, ?, ?, ?, ?, ?, ?, ?)").run(event.eventId, relativePath, event.ordinal, event.sequence, event.byteStart, event.byteEnd, event.occurredAt, event.kind);
        normalizeEvent(db, event);
      }
      db.prepare("UPDATE control_files SET status='ready', reason=NULL WHERE relative_path=?").run(relativePath);
    });
    changed ||= events.length > 0 || !previous || Number(previous.accepted_end) !== current.acceptedEnd || previous.prefix_hash !== current.prefixHash;
    await yieldToEventLoop();
  }
  const stale = db.prepare("SELECT relative_path FROM control_files WHERE relative_path LIKE 'events/%'").all().map((row) => String(row.relative_path)).filter((path) => !seen.has(path));
  for (const path of stale) {
    const oldIds = db.prepare("SELECT event_id FROM control_records WHERE relative_path=?").all(path).map((row) => String(row.event_id));
    withTransaction(db, () => { deleteEventData(db, oldIds); db.prepare("DELETE FROM control_records WHERE relative_path=?").run(path); db.prepare("DELETE FROM control_files WHERE relative_path=?").run(path); });
    changed = true;
  }
  resolvePendingLinks(db);
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
    let manifest: JsonRecord;
    try { manifest = validateControlManifest(parseCompleteJson(await readFile((await resolveRegularContainedPath(root, `${relativePath}/manifest.json`)).path, "utf8"), "planner manifest.json")); }
    catch { degraded = true; continue; }
    if (manifest.epochId !== epochId || manifest.plannerRunId !== runId) { degraded = true; continue; }
    let files: string[];
    try { files = await listRunFiles(root, relativePath); } catch { degraded = true; continue; }
    const declared = (manifest.files as JsonRecord[]).map((item) => String(item.path));
    if (declared.length !== files.length || declared.some((path, index) => path !== files[index])) { degraded = true; continue; }
    let valid = true;
    for (const item of manifest.files as JsonRecord[]) {
      try {
        const resolved = await resolveRegularContainedPath(root, `${relativePath}/${String(item.path)}`);
        if (resolved.stat.size !== Number(item.byteSize) || await prefixHash(resolved.path, resolved.stat.size) !== String(item.sha256)) { valid = false; break; }
      } catch { valid = false; break; }
    }
    const prior = db.prepare("SELECT status FROM control_artifacts WHERE planner_run_id=? LIMIT 1").get(runId);
    const priorArtifacts = db.prepare("SELECT relative_path, declared_size, declared_sha256, status FROM control_artifacts WHERE planner_run_id=? ORDER BY relative_path").all(runId);
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
      db.prepare("DELETE FROM control_artifacts WHERE planner_run_id=?").run(runId);
      for (const item of manifest.files as JsonRecord[]) db.prepare("INSERT INTO control_artifacts(planner_run_id, relative_path, media_type, availability, declared_size, declared_sha256, actual_size, status) VALUES(?, ?, ?, ?, ?, ?, ?, 'verified')").run(runId, String(item.path), mediaType(String(item.path)), String(item.availability), Number(item.byteSize), String(item.sha256), Number(item.byteSize));
      db.prepare("UPDATE control_planner_runs SET state=?, completed_at=coalesce(completed_at, ?), epoch_id=? WHERE planner_run_id=?").run(String(manifest.terminalState), String(manifest.completedAt), epochId, runId);
      if (!db.prepare("SELECT 1 FROM control_planner_runs WHERE planner_run_id=?").get(runId)) db.prepare("INSERT INTO control_planner_runs(planner_run_id, epoch_id, state, started_at, completed_at, input_signal_ids, active_task_ids, started_event_id, finished_event_id) VALUES(?, ?, ?, ?, ?, '[]', '[]', ?, NULL)").run(runId, epochId, String(manifest.terminalState), String(manifest.completedAt), String(manifest.completedAt), `manifest:${runId}`);
    });
    changed ||= artifactChanged || !prior;
  }
  return { changed, corrupt, degraded };
}

function domainStatus(db: DatabaseSync) {
  return db.prepare("SELECT state, epoch_id, last_error_category, last_success_at FROM domain_health WHERE domain='control-loop'").get();
}

export async function reconcileControlLoop(db: DatabaseSync, config: ArchiveConfig): Promise<ControlLoopReconcileResult> {
  const attemptedAt = now();
  if (!config.controlLoopRoot) {
    db.prepare(`INSERT INTO domain_health(domain, state, last_attempt_at, last_error_category, last_error_count) VALUES('control-loop', 'unavailable', ?, 'root-unconfigured', 1) ON CONFLICT(domain) DO UPDATE SET state='unavailable',last_attempt_at=excluded.last_attempt_at,last_error_category=excluded.last_error_category,last_error_count=1`).run(attemptedAt);
    return { changed: false, state: "unavailable", epochId: null, errorCategory: "root-unconfigured", lastSuccessAt: null };
  }
  try {
    await assertDirectoryRoot(config.controlLoopRoot);
  } catch {
    db.prepare(`INSERT INTO domain_health(domain, state, last_attempt_at, last_error_category, last_error_count) VALUES('control-loop', 'unavailable', ?, 'root-unavailable', 1) ON CONFLICT(domain) DO UPDATE SET state='unavailable',last_attempt_at=excluded.last_attempt_at,last_error_category=excluded.last_error_category,last_error_count=1`).run(attemptedAt);
    return { changed: false, state: "unavailable", epochId: null, errorCategory: "root-unavailable", lastSuccessAt: null };
  }
  let epoch: ReturnType<typeof validateControlEpoch>;
  try { epoch = validateControlEpoch(parseCompleteJson(await readFile((await resolveRegularContainedPath(config.controlLoopRoot, "epoch.json")).path, "utf8"), "control-loop epoch.json")); }
  catch {
    db.prepare(`INSERT INTO domain_health(domain, state, last_attempt_at, last_error_category, last_error_count) VALUES('control-loop', 'degraded', ?, 'epoch-invalid', 1) ON CONFLICT(domain) DO UPDATE SET state='degraded',last_attempt_at=excluded.last_attempt_at,last_error_category=excluded.last_error_category,last_error_count=1`).run(attemptedAt);
    return { changed: false, state: "degraded", epochId: null, errorCategory: "epoch-invalid", lastSuccessAt: null };
  }
  const prior = domainStatus(db);
  const taskEpoch = readDatabaseMeta(db).epochId;
  if ((prior?.epoch_id && String(prior.epoch_id) !== epoch.epochId) || (taskEpoch && taskEpoch !== epoch.epochId)) {
    db.prepare(`INSERT INTO domain_health(domain, state, epoch_id, last_attempt_at, last_error_category, last_error_count) VALUES('control-loop', 'incompatible', ?, ?, 'epoch-mismatch', 1) ON CONFLICT(domain) DO UPDATE SET state='incompatible',epoch_id=excluded.epoch_id,last_attempt_at=excluded.last_attempt_at,last_error_category=excluded.last_error_category,last_error_count=1`).run(epoch.epochId, attemptedAt);
    return { changed: false, state: "incompatible", epochId: epoch.epochId, errorCategory: "epoch-mismatch", lastSuccessAt: null };
  }
  db.prepare(`INSERT INTO domain_health(domain, state, epoch_id, last_attempt_at, last_error_category, last_error_count) VALUES('control-loop', 'indexing', ?, ?, NULL, 0) ON CONFLICT(domain) DO UPDATE SET state='indexing',epoch_id=excluded.epoch_id,last_attempt_at=excluded.last_attempt_at,last_error_category=NULL,last_error_count=0`).run(epoch.epochId, attemptedAt);
  const eventResult = await reconcileEvents(db, config.controlLoopRoot, epoch.epochId);
  const currentResult = await reconcileCurrent(db, config.controlLoopRoot, epoch.epochId);
  const runResult = await reconcileRuns(db, config.controlLoopRoot, epoch.epochId);
  resolvePendingLinks(db);
  const changed = eventResult.changed || currentResult.changed || runResult.changed;
  const state: ControlLoopState = runResult.corrupt ? "archive-corrupt" : eventResult.degraded || currentResult.degraded || runResult.degraded ? "degraded" : "ready";
  const succeededAt = now();
  db.prepare(`UPDATE domain_health SET state=?, root_revision=?, last_success_at=?, last_error_category=?, last_error_count=?, lag_seconds=0 WHERE domain='control-loop'`).run(state, `epoch:${epoch.epochId}`, succeededAt, state === "ready" ? null : runResult.corrupt ? "archive-corrupt" : "control-loop-pending", state === "ready" ? 0 : 1);
  return { changed, state, epochId: epoch.epochId, errorCategory: state === "ready" ? null : runResult.corrupt ? "archive-corrupt" : "control-loop-pending", lastSuccessAt: succeededAt };
}

export async function readControlEventRecord(root: string, relativePath: string, start: number, end: number) {
  const resolved = await resolveRegularContainedPath(root, relativePath);
  const bytes = await readFile(resolved.path);
  if (start < 0 || end <= start || end > bytes.length || bytes[end - 1] !== 10) throw new Error("control-loop event cursor is stale");
  return validateControlEvent(parseCompleteJson(bytes.subarray(start, end - 1).toString("utf8"), relativePath));
}

export async function openControlArtifact(root: string, relativePath: string) {
  return resolveRegularContainedPath(root, relativePath);
}

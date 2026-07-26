import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { appendFile, cp, mkdir, mkdtemp, open, readFile, rename, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { getArchiveConfig } from "@/lib/steward-archive/config";
import { DATABASE_SCHEMA_VERSION, openArchiveDatabase } from "@/lib/steward-archive/database";
import { StewardArchiveImporter } from "@/lib/steward-archive/importer";
import { StewardArchiveRepository } from "@/lib/steward-archive/repository";
import { resolveArchiveSelection } from "@/app/steward/archive-selection";
import { mergeEvidenceRecords, refreshEvidenceFrontier } from "@/app/steward/control-loop-evidence";

async function fixture() {
  const root = await mkdtemp(join(tmpdir(), "coquic-control-loop-"));
  const tasksRoot = join(root, "tasks");
  const controlLoopRoot = join(root, "control-loop");
  const cachePath = join(root, "cache", "site-v2.sqlite");
  await cp(new URL("../../examples/steward-dataset", import.meta.url), tasksRoot, { recursive: true });
  await cp(new URL("../../examples/steward-control-loop", import.meta.url), controlLoopRoot, { recursive: true });
  const config = getArchiveConfig({ NODE_ENV: "test", COQUIC_STEWARD_TASKS_ROOT: tasksRoot, COQUIC_STEWARD_CONTROL_LOOP_ROOT: controlLoopRoot, COQUIC_STEWARD_CACHE_PATH: cachePath, COQUIC_STEWARD_BATCH_SIZE: "3" });
  const importer = new StewardArchiveImporter(config);
  await importer.reconcile();
  return { root, tasksRoot, controlLoopRoot, importer, repository: new StewardArchiveRepository(importer) };
}

test("control-loop configuration rejects relative and unsafe roots", () => {
  assert.throws(() => getArchiveConfig({ NODE_ENV: "test", COQUIC_STEWARD_TASKS_ROOT: "/tmp/tasks", COQUIC_STEWARD_CONTROL_LOOP_ROOT: "control-loop", COQUIC_STEWARD_CACHE_PATH: "/tmp/cache/site-v2.sqlite" }), /absolute/);
  assert.throws(() => getArchiveConfig({ NODE_ENV: "test", COQUIC_STEWARD_TASKS_ROOT: "/tmp/tasks", COQUIC_STEWARD_CONTROL_LOOP_ROOT: "/tmp/control\\loop", COQUIC_STEWARD_CACHE_PATH: "/tmp/cache/site-v2.sqlite" }), /unsafe/);
});

test("control-loop importer indexes normalized records and keeps revisions idempotent", async (t) => {
  const state = await fixture();
  t.after(() => { state.importer.db.close(); return rm(state.root, { recursive: true, force: true }); });
  assert.equal(state.importer.db.prepare("SELECT count(*) AS count FROM control_records").get()?.count, 39);
  assert.equal(state.importer.db.prepare("SELECT count(*) AS count FROM control_signals").get()?.count, 3);
  assert.equal(state.importer.db.prepare("SELECT count(*) AS count FROM control_proposals").get()?.count, 5);
  assert.equal(state.importer.db.prepare("SELECT count(*) AS count FROM control_artifacts WHERE status='verified'").get()?.count, 10);
  const revision = state.importer.revision().revision;
  await state.importer.reconcile();
  assert.equal(state.importer.revision().revision, revision);
  assert.equal(state.repository.listSignalsPage().total, 3);
  assert.equal(state.repository.listPlannerRunsPage().total, 2);
});

test("complete-line append, partial tails, and replacement retain safe evidence", async (t) => {
  const state = await fixture();
  t.after(() => { state.importer.db.close(); return rm(state.root, { recursive: true, force: true }); });
  const path = join(state.controlLoopRoot, "events/2026/07/24.jsonl");
  const original = await readFile(path, "utf8");
  const before = state.repository.getSignalDetail("signal-synthetic-open");
  await appendFile(path, "{\"eventId\":\"partial-tail\"");
  await state.importer.reconcile();
  assert.equal(state.importer.db.prepare("SELECT count(*) AS count FROM control_records").get()?.count, 39);
  assert.equal(state.importer.db.prepare("SELECT state FROM domain_health WHERE domain='control-loop'").get()?.state, "degraded");
  await writeFile(path, `${original}${JSON.stringify({ eventId: "event-runtime-extra", epochId: "epoch-synthetic-20260722", sequence: 39, occurredAt: "2026-07-24T12:06:00Z", kind: "daemon.runtime", payload: { state: "running", instanceId: "instance-extra" } })}\n`);
  await state.importer.reconcile();
  assert.equal(state.importer.db.prepare("SELECT count(*) AS count FROM control_records").get()?.count, 40);
  assert.equal(state.repository.getSignalDetail("signal-synthetic-open")?.eventCount, before?.eventCount);
});

test("F001 incomplete event replacement retains the last valid generation", async (t) => {
  const state = await fixture();
  t.after(() => { state.importer.db.close(); return rm(state.root, { recursive: true, force: true }); });
  const path = join(state.controlLoopRoot, "events/2026/07/24.jsonl");
  const firstRecord = (await readFile(path, "utf8")).split("\n")[0];
  await writeFile(path, `${firstRecord}\n{"eventId":"partial-replacement"`);
  await state.importer.reconcile();
  assert.equal(state.importer.db.prepare("SELECT count(*) AS count FROM control_records").get()?.count, 39);
  assert.equal(state.importer.db.prepare("SELECT state FROM domain_health WHERE domain='control-loop'").get()?.state, "degraded");
});

test("F002 unordered event files replay normalized signal state by archive sequence", async (t) => {
  const state = await fixture();
  t.after(() => { state.importer.db.close(); return rm(state.root, { recursive: true, force: true }); });
  const directory = join(state.controlLoopRoot, "events/2026/07");
  const transition = { eventId: "event-unordered-transition", epochId: "epoch-synthetic-20260722", sequence: 40, occurredAt: "2026-07-26T00:00:00Z", kind: "signal.transition", payload: { transition: { signalId: "signal-unordered", fromStatus: "pending", toStatus: "planned", plannerRunId: "planner-synthetic-success", reasonCode: "planner_consumed" } } };
  await writeFile(join(directory, "26.jsonl"), `${JSON.stringify(transition)}\n`);
  await state.importer.reconcile();
  assert.equal(state.repository.getSignalDetail("signal-unordered"), null);
  const created = { eventId: "event-unordered-created", epochId: "epoch-synthetic-20260722", sequence: 39, occurredAt: "2026-07-25T00:00:00Z", kind: "signal.created", payload: { signal: { signalId: "signal-unordered", provider: "synthetic-a", fingerprint: "fingerprint-unordered", status: "pending", createdAt: "2026-07-25T00:00:00Z", updatedAt: "2026-07-25T00:00:00Z", transition: null } } };
  await writeFile(join(directory, "25.jsonl"), `${JSON.stringify(created)}\n`);
  await state.importer.reconcile();
  const signal = state.importer.db.prepare("SELECT status, transition_reason FROM control_signals WHERE signal_id=?").get("signal-unordered");
  assert.equal(signal?.status, "planned");
  assert.equal(signal?.transition_reason, "planner_consumed");
});

test("F003 mutation of a verified planner manifest marks retained artifacts corrupt", async (t) => {
  const state = await fixture();
  t.after(() => { state.importer.db.close(); return rm(state.root, { recursive: true, force: true }); });
  const path = join(state.controlLoopRoot, "planner-runs/planner-synthetic-success/manifest.json");
  await appendFile(path, "garbage");
  await state.importer.reconcile();
  assert.equal(state.importer.db.prepare("SELECT state FROM domain_health WHERE domain='control-loop'").get()?.state, "archive-corrupt");
  assert.equal(state.importer.db.prepare("SELECT count(*) AS count FROM control_artifacts WHERE planner_run_id=? AND status='corrupt'").get("planner-synthetic-success")?.count, 5);
});

test("F004 domain health remains independent across an epoch mismatch", async (t) => {
  const state = await fixture();
  t.after(() => { state.importer.db.close(); return rm(state.root, { recursive: true, force: true }); });
  const epochPath = join(state.controlLoopRoot, "epoch.json");
  await writeFile(epochPath, (await readFile(epochPath, "utf8")).replace("epoch-synthetic-20260722", "epoch-other"));
  await state.importer.reconcile();
  const health = Object.fromEntries(state.repository.getDomainHealth().map((domain) => [domain.domain, domain.state]));
  assert.deepEqual(health, { tasks: "ready", "control-loop": "incompatible" });
});

test("F005 control-loop health-only changes advance the shared revision", async (t) => {
  const state = await fixture();
  t.after(() => { state.importer.db.close(); return rm(state.root, { recursive: true, force: true }); });
  const revision = state.importer.revision().revision;
  await appendFile(join(state.controlLoopRoot, "events/2026/07/24.jsonl"), "{\"eventId\":\"partial-tail\"");
  await state.importer.reconcile();
  assert.equal(state.importer.db.prepare("SELECT state FROM domain_health WHERE domain='control-loop'").get()?.state, "degraded");
  assert(state.importer.revision().revision > revision);
});

test("F006 a stable signal deep link resolves outside the first 50-row page", async (t) => {
  const state = await fixture();
  t.after(() => { state.importer.db.close(); return rm(state.root, { recursive: true, force: true }); });
  const insert = state.importer.db.prepare("INSERT INTO control_signals(signal_id, provider, fingerprint, status, created_at, updated_at, transition_reason, event_id) VALUES(?, 'synthetic-a', ?, 'pending', ?, ?, NULL, ?)");
  for (let index = 0; index < 51; index += 1) {
    const suffix = String(index).padStart(2, "0");
    insert.run(`signal-deep-link-${suffix}`, `fingerprint-deep-link-${suffix}`, `2026-08-01T00:00:${suffix}Z`, `2026-08-01T00:00:${suffix}Z`, `event-deep-link-${suffix}`);
  }
  const target = "signal-deep-link-00";
  const page = state.repository.listSignalsPage();
  assert.equal(page.items.length, 50);
  assert.equal(page.items.some((signal) => signal.signalId === target), false);
  const selected = resolveArchiveSelection(target, page.items[0]?.signalId, (id) => state.repository.getSignalDetail(id));
  assert.equal(selected?.signalId, target);
});

test("malformed event replacement keeps the last valid generation queryable", async (t) => {
  const state = await fixture();
  t.after(() => { state.importer.db.close(); return rm(state.root, { recursive: true, force: true }); });
  const path = join(state.controlLoopRoot, "events/2026/07/24.jsonl");
  const original = await readFile(path, "utf8");
  await writeFile(path, `${original}{malformed}\n`);
  await state.importer.reconcile();
  assert.equal(state.importer.db.prepare("SELECT state FROM domain_health WHERE domain='control-loop'").get()?.state, "degraded");
  const evidence = await state.repository.readSignalEvents("signal-synthetic-open", null, 100);
  assert(evidence); assert(evidence.records.length > 0);
});

test("selected readers expose complete records and manifest-verified downloads only", async (t) => {
  const state = await fixture();
  t.after(() => { state.importer.db.close(); return rm(state.root, { recursive: true, force: true }); });
  const events = await state.repository.readSignalEvents("signal-synthetic-consumed", null, 2);
  assert(events); assert.equal(events.records.length, 2); assert(events.nextCursor);
  const continued = await state.repository.readSignalEvents("signal-synthetic-consumed", events.nextCursor, 20);
  assert(continued); assert.equal(new Set([...events.records, ...continued.records].map((record) => record.eventId)).size, 11);
  const transcript = await state.repository.readPlannerTranscript("planner-synthetic-success");
  assert(transcript); assert.equal(transcript.records.length, 2); assert.equal(transcript.incompleteTail, false);
  const artifact = await state.repository.readPlannerArtifact("planner-synthetic-success", "prompt.md");
  const chunks: Buffer[] = []; for await (const chunk of artifact.stream) chunks.push(Buffer.from(chunk));
  assert.match(Buffer.concat(chunks).toString("utf8"), /Current signal/);
  assert.equal(state.repository.getTaskProvenance("task-synthetic-accepted"), null);
  state.importer.db.prepare("INSERT INTO tasks(task_id, epoch_id, status, title, summary, prompt_path, events_path, current_pipeline_id, created_at, updated_at, archive_state, root_relative_path) SELECT 'task-synthetic-accepted', epoch_id, status, title, summary, prompt_path, events_path, current_pipeline_id, created_at, updated_at, archive_state, root_relative_path FROM tasks LIMIT 1").run();
  assert(state.repository.getTaskProvenance("task-synthetic-accepted"));
  state.importer.db.prepare("DELETE FROM control_edges WHERE edge_type='proposal_task' AND target_id=?").run("task-synthetic-accepted");
  assert.equal(state.repository.getTaskProvenance("task-synthetic-accepted"), null);
});

test("peer epoch mismatch preserves the last compatible control-loop generation", async (t) => {
  const state = await fixture();
  t.after(() => { state.importer.db.close(); return rm(state.root, { recursive: true, force: true }); });
  const epochPath = join(state.controlLoopRoot, "epoch.json");
  const original = await readFile(epochPath, "utf8");
  await writeFile(epochPath, original.replace("epoch-synthetic-20260722", "epoch-other"));
  await state.importer.reconcile();
  assert.equal(state.importer.db.prepare("SELECT state FROM domain_health WHERE domain='control-loop'").get()?.state, "incompatible");
  assert.equal(state.importer.db.prepare("SELECT count(*) AS count FROM control_records").get()?.count, 39);
});

test("F008 large event replacement is staged in bounded batches before generation swap", async (t) => {
  const state = await fixture();
  t.after(() => { state.importer.db.close(); return rm(state.root, { recursive: true, force: true }); });
  const path = join(state.controlLoopRoot, "events/2026/07/24.jsonl");
  const records = Array.from({ length: 257 }, (_, sequence) => JSON.stringify({ eventId: `event-large-${sequence}`, epochId: "epoch-synthetic-20260722", sequence, occurredAt: `2026-07-25T00:${String(Math.floor(sequence / 60)).padStart(2, "0")}:${String(sequence % 60).padStart(2, "0")}Z`, kind: "daemon.runtime", payload: { state: "running", instanceId: `instance-${sequence}` } }));
  await writeFile(path, `${records.join("\n")}\n`);
  await state.importer.reconcile();
  assert.equal(state.importer.db.prepare("SELECT count(*) AS count FROM control_records").get()?.count, 257);
  assert.equal(state.importer.db.prepare("SELECT count(*) AS count FROM control_record_staging").get()?.count, 0);
  assert.equal(state.importer.db.prepare("SELECT count(*) AS count FROM control_normalized_staging").get()?.count, 0);
  assert.equal(state.importer.db.prepare("SELECT complete_records FROM control_files WHERE relative_path='events/2026/07/24.jsonl'").get()?.complete_records, 257);

  const august = join(state.controlLoopRoot, "events/2026/08");
  await mkdir(august, { recursive: true });
  for (let index = 0; index < 12; index += 1) {
    const sequence = 257 + index;
    const event = { eventId: `event-ledger-${sequence}`, epochId: "epoch-synthetic-20260722", sequence, occurredAt: `2026-08-${String(index + 1).padStart(2, "0")}T00:00:00Z`, kind: "daemon.runtime", payload: { state: "running", instanceId: `instance-ledger-${sequence}` } };
    await writeFile(join(august, `${String(index + 1).padStart(2, "0")}.jsonl`), `${JSON.stringify(event)}\n`);
  }
  await state.importer.reconcile();
  assert.equal(state.importer.db.prepare("SELECT count(*) AS count FROM control_records").get()?.count, 269);

  await rm(join(august, "01.jsonl"));
  await state.importer.reconcile();
  assert.equal(state.importer.db.prepare("SELECT count(*) AS count FROM control_records WHERE event_id='event-ledger-257'").get()?.count, 0);
  assert.equal(state.importer.db.prepare("SELECT count(*) AS count FROM control_records").get()?.count, 268);
});

test("F009 duplicate same-file append rejects the complete append atomically", async (t) => {
  const state = await fixture();
  t.after(() => { state.importer.db.close(); return rm(state.root, { recursive: true, force: true }); });
  const path = join(state.controlLoopRoot, "events/2026/07/24.jsonl");
  const valid = { eventId: "event-before-conflict", epochId: "epoch-synthetic-20260722", sequence: 39, occurredAt: "2026-07-25T00:00:00Z", kind: "daemon.runtime", payload: { state: "running", instanceId: "candidate" } };
  const duplicate = { eventId: "event-fetch-a", epochId: "epoch-synthetic-20260722", sequence: 40, occurredAt: "2026-07-25T00:00:01Z", kind: "daemon.runtime", payload: { state: "running", instanceId: "duplicate" } };
  await appendFile(path, `${JSON.stringify(valid)}\n${JSON.stringify(duplicate)}\n`);
  await state.importer.reconcile();
  assert.equal(state.importer.db.prepare("SELECT count(*) AS count FROM control_records").get()?.count, 39);
  assert.equal(state.importer.db.prepare("SELECT count(*) AS count FROM control_records WHERE event_id='event-fetch-a'").get()?.count, 1);
  assert.equal(state.importer.db.prepare("SELECT count(*) AS count FROM control_records WHERE event_id='event-before-conflict'").get()?.count, 0);
  assert.equal(state.importer.db.prepare("SELECT count(*) AS count FROM control_record_staging").get()?.count, 0);
});

test("F010 planner transcript byte cursors preserve long and arbitrary compatible fields", async (t) => {
  const state = await fixture();
  t.after(() => { state.importer.db.close(); return rm(state.root, { recursive: true, force: true }); });
  const runId = "planner-large-transcript";
  const directory = join(state.controlLoopRoot, "planner-runs", runId);
  await mkdir(directory, { recursive: true });
  const longText = "x".repeat(20_000);
  const source = `${JSON.stringify({ record_type: "assistant.message", text: longText, compatible: { nested: [1, 2, 3] }, arbitraryField: "preserved" })}\n${JSON.stringify({ type: "future.record", future: true, payload: { answer: 42 } })}\n`;
  const artifactPath = join(directory, "codex.jsonl");
  await writeFile(artifactPath, source);
  const sha256 = createHash("sha256").update(source).digest("hex");
  const identity = await stat(artifactPath, { bigint: true });
  state.importer.db.prepare("INSERT INTO control_planner_runs(planner_run_id, epoch_id, state, started_at, completed_at, input_signal_ids, active_task_ids, started_event_id, finished_event_id) VALUES(?, 'epoch-synthetic-20260722', 'succeeded', '2026-07-25T00:00:00Z', '2026-07-25T00:00:01Z', '[]', '[]', ?, NULL)").run(runId, `manifest:${runId}`);
  state.importer.db.prepare("INSERT INTO control_artifacts(planner_run_id, relative_path, media_type, availability, declared_size, declared_sha256, actual_size, device_id, inode_id, mtime_ns, ctime_ns, status) VALUES(?, 'codex.jsonl', 'application/x-ndjson', 'available', ?, ?, ?, ?, ?, ?, ?, 'verified')").run(runId, Buffer.byteLength(source), sha256, Buffer.byteLength(source), String(identity.dev), String(identity.ino), String(identity.mtimeNs), String(identity.ctimeNs));

  const probe = await open(artifactPath, "r");
  const prototype = Object.getPrototypeOf(probe) as { read: (...args: unknown[]) => Promise<{ bytesRead: number }> };
  const originalRead = prototype.read;
  await probe.close();
  let bytesRead = 0;
  t.mock.method(prototype, "read", async function (this: object, ...args: unknown[]) {
    const result = await originalRead.apply(this, args);
    bytesRead += result.bytesRead;
    return result;
  });
  const first = await state.repository.readPlannerTranscript(runId, null, 1);
  assert(first); assert.equal(first.records[0].value.text, longText); assert.deepEqual(first.records[0].value.compatible, { nested: [1, 2, 3] }); assert(first.nextCursor);
  assert(bytesRead <= Buffer.byteLength(source));
  bytesRead = 0;
  const second = await state.repository.readPlannerTranscript(runId, first.nextCursor, 1);
  assert(second); assert.deepEqual(second.records[0].value, { type: "future.record", future: true, payload: { answer: 42 } }); assert.equal(second.nextCursor, null);
  assert(bytesRead < Buffer.byteLength(source));

  await writeFile(artifactPath, source.replace("future.record", "future.recorx"));
  bytesRead = 0;
  await assert.rejects(() => state.repository.readPlannerTranscript(runId, first.nextCursor, 1), (error: Error & { code?: string }) => error.code === "STALE_CURSOR");
  assert.equal(bytesRead, 0);
});

test("F010 schema migration adds validated planner artifact identities", async () => {
  const root = await mkdtemp(join(tmpdir(), "coquic-control-schema-"));
  const cachePath = join(root, "cache", "site-v2.sqlite");
  try {
    const previous = openArchiveDatabase(cachePath);
    try {
      previous.exec(`
        ALTER TABLE control_artifacts RENAME TO control_artifacts_v7;
        CREATE TABLE control_artifacts (
          planner_run_id TEXT NOT NULL,
          relative_path TEXT NOT NULL,
          media_type TEXT,
          availability TEXT NOT NULL,
          declared_size INTEGER NOT NULL,
          declared_sha256 TEXT NOT NULL,
          actual_size INTEGER,
          status TEXT NOT NULL DEFAULT 'pending',
          PRIMARY KEY(planner_run_id, relative_path)
        );
        DROP TABLE control_artifacts_v7;
        UPDATE archive_meta SET schema_version=6 WHERE singleton=1;
      `);
    } finally { previous.close(); }

    const migrated = openArchiveDatabase(cachePath);
    try {
      assert.equal(migrated.prepare("SELECT schema_version FROM archive_meta WHERE singleton=1").get()?.schema_version, DATABASE_SCHEMA_VERSION);
      const columns = new Set(migrated.prepare("PRAGMA table_info(control_artifacts)").all().map((row) => String(row.name)));
      assert.deepEqual([...columns].filter((column) => ["device_id", "inode_id", "mtime_ns", "ctime_ns"].includes(column)), ["device_id", "inode_id", "mtime_ns", "ctime_ns"]);
    } finally { migrated.close(); }
  } finally { await rm(root, { recursive: true, force: true }); }
});

test("F011 unchanged invalid and unavailable control-loop health keeps revision stable", async (t) => {
  const state = await fixture();
  t.after(() => { state.importer.db.close(); return rm(state.root, { recursive: true, force: true }); });
  await writeFile(join(state.controlLoopRoot, "epoch.json"), "{invalid}\n");
  await state.importer.reconcile();
  const invalidRevision = state.importer.revision().revision;
  await state.importer.reconcile();
  assert.equal(state.importer.revision().revision, invalidRevision);
  const unavailableRoot = `${state.controlLoopRoot}-away`;
  await rename(state.controlLoopRoot, unavailableRoot);
  await state.importer.reconcile();
  const unavailableRevision = state.importer.revision().revision;
  await state.importer.reconcile();
  assert.equal(state.importer.revision().revision, unavailableRevision);
  await rename(unavailableRoot, state.controlLoopRoot);
});

test("F012 and F013 planner detail requires an explicit task edge and exposes wakeup/current evidence", async (t) => {
  const state = await fixture();
  t.after(() => { state.importer.db.close(); return rm(state.root, { recursive: true, force: true }); });
  state.importer.db.prepare("INSERT INTO tasks(task_id, epoch_id, status, title, summary, prompt_path, events_path, current_pipeline_id, created_at, updated_at, archive_state, root_relative_path) SELECT 'task-synthetic-accepted', epoch_id, status, title, summary, prompt_path, events_path, current_pipeline_id, created_at, updated_at, archive_state, root_relative_path FROM tasks LIMIT 1").run();
  let detail = state.repository.getPlannerRunDetail("planner-synthetic-success");
  assert(detail);
  assert.equal(detail.proposals.find((proposal) => proposal.proposalId === "proposal-synthetic-1")?.taskAvailable, true);
  state.importer.db.prepare("DELETE FROM control_edges WHERE edge_type='proposal_task' AND source_id='proposal-synthetic-1'").run();
  detail = state.repository.getPlannerRunDetail("planner-synthetic-success");
  assert(detail);
  assert.equal(detail.proposals.find((proposal) => proposal.proposalId === "proposal-synthetic-1")?.taskAvailable, false);
  assert.equal(state.repository.getSignalDetail("signal-synthetic-consumed")?.proposals.find((proposal) => proposal.proposalId === "proposal-synthetic-1")?.taskAvailable, false);
  assert.equal(detail.wakeups[0]?.wakeupId, "wakeup-synthetic-1");
  assert.deepEqual(detail.wakeups[0]?.inputSignalIds, ["signal-synthetic-consumed"]);
  assert.equal(detail.current?.status, "ready");
});

test("F014 an end cursor resumes newly indexed signal evidence without duplication", async (t) => {
  const state = await fixture();
  t.after(() => { state.importer.db.close(); return rm(state.root, { recursive: true, force: true }); });
  const first = await state.repository.readSignalEvents("signal-synthetic-open", null, 100);
  assert(first); assert.equal(first.nextCursor, null); assert(first.resumeCursor);
  const appended = { eventId: "event-open-refresh", epochId: "epoch-synthetic-20260722", sequence: 39, occurredAt: "2026-07-25T00:00:00Z", kind: "signal.transition", payload: { transition: { signalId: "signal-synthetic-open", fromStatus: "pending", toStatus: "planned", plannerRunId: "planner-synthetic-success", reasonCode: "planner_consumed" } } };
  await appendFile(join(state.controlLoopRoot, "events/2026/07/24.jsonl"), `${JSON.stringify(appended)}\n`);
  await state.importer.reconcile();
  const resumed = await state.repository.readSignalEvents("signal-synthetic-open", first.resumeCursor, 100);
  assert(resumed); assert.deepEqual(resumed.records.map((record) => record.eventId), ["event-open-refresh"]);
  assert.equal(new Set([...first.records, ...resumed.records].map((record) => record.eventId)).size, first.records.length + 1);
});

test("F014 stale refresh crosses an exact page boundary through the refreshed frontier", async () => {
  const loaded = Array.from({ length: 50 }, (_, index) => ({ eventId: `event-refresh-${index}`, sequence: index }));
  const requested: Array<string | null> = [];
  const refreshed = await refreshEvidenceFrontier(async (cursor) => {
    requested.push(cursor);
    if (cursor === "stale") throw Object.assign(new Error("stale"), { status: 409 });
    if (cursor === null) return { records: loaded, nextCursor: "next-page", resumeCursor: "first-page-end" };
    return { records: [{ eventId: "event-refresh-50", sequence: 50 }], nextCursor: null, resumeCursor: "refreshed-frontier" };
  }, "stale", (record) => String(record.eventId));
  const visible = mergeEvidenceRecords(loaded, refreshed.records, (record) => String(record.eventId));
  assert.deepEqual(requested, ["stale", null, "next-page"]);
  assert.equal(refreshed.resumeCursor, "refreshed-frontier");
  assert.equal(visible.length, 51);
  assert.equal(visible.at(-1)?.eventId, "event-refresh-50");
});

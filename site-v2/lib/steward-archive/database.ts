import { DatabaseSync } from "node:sqlite";
import { dirname, resolve } from "node:path";
import { mkdirSync } from "node:fs";

export const DATABASE_SCHEMA_VERSION = 4;

export interface DatabaseMeta {
  state: string;
  epochId: string | null;
  revision: number;
  lastAttemptAt: string | null;
  lastSuccessAt: string | null;
  lastErrorCategory: string | null;
  lastErrorCount: number;
  schemaVersion: number;
}

export function openArchiveDatabase(cachePath: string) {
  mkdirSync(dirname(resolve(cachePath)), { recursive: true });
  const db = new DatabaseSync(cachePath);
  db.exec("PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;");
  db.exec(`
    CREATE TABLE IF NOT EXISTS archive_meta (
      singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
      schema_version INTEGER NOT NULL,
      state TEXT NOT NULL,
      epoch_id TEXT,
      revision INTEGER NOT NULL DEFAULT 0,
      last_attempt_at TEXT,
      last_success_at TEXT,
      last_error_category TEXT,
      last_error_count INTEGER NOT NULL DEFAULT 0,
      last_scan_duration_ms INTEGER,
      watch_state TEXT NOT NULL DEFAULT 'stopped'
    );
    CREATE TABLE IF NOT EXISTS tasks (
      task_id TEXT PRIMARY KEY,
      epoch_id TEXT NOT NULL,
      status TEXT NOT NULL,
      title TEXT NOT NULL,
      summary TEXT NOT NULL,
      prompt_path TEXT NOT NULL,
      events_path TEXT NOT NULL,
      current_pipeline_id TEXT,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      archive_state TEXT NOT NULL DEFAULT 'live',
      manifest_observed_at TEXT,
      verified_at TEXT,
      archive_reason TEXT,
      last_import_at TEXT,
      root_relative_path TEXT NOT NULL,
      UNIQUE(epoch_id, task_id)
    );
    CREATE INDEX IF NOT EXISTS tasks_state_updated ON tasks(status, updated_at DESC, task_id);
    CREATE INDEX IF NOT EXISTS tasks_updated ON tasks(updated_at DESC, task_id);
    CREATE TABLE IF NOT EXISTS pipelines (
      task_id TEXT NOT NULL REFERENCES tasks(task_id) ON DELETE CASCADE,
      pipeline_id TEXT NOT NULL,
      ordinal INTEGER NOT NULL,
      trigger TEXT NOT NULL,
      parent_pipeline_id TEXT,
      phase TEXT NOT NULL,
      state TEXT NOT NULL,
      started_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      completed_at TEXT,
      metadata_path TEXT NOT NULL,
      PRIMARY KEY(task_id, pipeline_id)
    );
    CREATE TABLE IF NOT EXISTS runs (
      task_id TEXT NOT NULL REFERENCES tasks(task_id) ON DELETE CASCADE,
      pipeline_id TEXT NOT NULL,
      run_id TEXT NOT NULL,
      role TEXT NOT NULL,
      role_ordinal INTEGER NOT NULL,
      session_id TEXT NOT NULL,
      resume_of_run_id TEXT,
      parent_run_id TEXT,
      retry_of_run_id TEXT,
      state TEXT NOT NULL,
      started_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      completed_at TEXT,
      model TEXT,
      reasoning TEXT,
      metadata_path TEXT NOT NULL,
      PRIMARY KEY(task_id, run_id),
      FOREIGN KEY(task_id, pipeline_id) REFERENCES pipelines(task_id, pipeline_id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS runs_lookup ON runs(task_id, pipeline_id, role_ordinal);
    CREATE TABLE IF NOT EXISTS usage_facts (
      task_id TEXT NOT NULL,
      run_id TEXT NOT NULL,
      availability TEXT NOT NULL,
      prompt_tokens INTEGER,
      completion_tokens INTEGER,
      total_tokens INTEGER,
      source_path TEXT,
      reason TEXT,
      cost_availability TEXT NOT NULL,
      estimated_micro_usd INTEGER,
      cost_model TEXT,
      pricing_source TEXT,
      cost_reason TEXT,
      PRIMARY KEY(task_id, run_id),
      FOREIGN KEY(task_id, run_id) REFERENCES runs(task_id, run_id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS usage_available ON usage_facts(availability, cost_availability);
    CREATE TABLE IF NOT EXISTS files (
      task_id TEXT NOT NULL REFERENCES tasks(task_id) ON DELETE CASCADE,
      relative_path TEXT NOT NULL,
      kind TEXT NOT NULL,
      media_type TEXT,
      lifecycle TEXT,
      declared_size INTEGER,
      declared_sha256 TEXT,
      actual_size INTEGER,
      accepted_end INTEGER NOT NULL DEFAULT 0,
      prefix_hash TEXT,
      prefix_revision INTEGER NOT NULL DEFAULT 0,
      complete_records INTEGER NOT NULL DEFAULT 0,
      file_revision TEXT,
      device_id TEXT,
      inode_id TEXT,
      mtime_ns TEXT,
      ctime_ns TEXT,
      status TEXT NOT NULL DEFAULT 'pending',
      PRIMARY KEY(task_id, relative_path)
    );
    CREATE INDEX IF NOT EXISTS files_lookup ON files(task_id, relative_path, prefix_revision);
    CREATE TABLE IF NOT EXISTS records (
      task_id TEXT NOT NULL REFERENCES tasks(task_id) ON DELETE CASCADE,
      relative_path TEXT NOT NULL,
      ordinal INTEGER NOT NULL,
      byte_start INTEGER NOT NULL,
      byte_end INTEGER NOT NULL,
      timestamp TEXT,
      record_type TEXT,
      PRIMARY KEY(task_id, relative_path, ordinal),
      FOREIGN KEY(task_id, relative_path) REFERENCES files(task_id, relative_path) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS record_staging (
      import_token TEXT NOT NULL,
      task_id TEXT NOT NULL,
      relative_path TEXT NOT NULL,
      ordinal INTEGER NOT NULL,
      byte_start INTEGER NOT NULL,
      byte_end INTEGER NOT NULL,
      timestamp TEXT,
      record_type TEXT,
      PRIMARY KEY(import_token, relative_path, ordinal)
    );
    CREATE INDEX IF NOT EXISTS record_staging_import ON record_staging(import_token, relative_path, ordinal);
    CREATE TABLE IF NOT EXISTS importer_errors (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      task_id TEXT,
      category TEXT NOT NULL,
      count INTEGER NOT NULL DEFAULT 1,
      first_seen_at TEXT NOT NULL,
      last_seen_at TEXT NOT NULL,
      UNIQUE(task_id, category)
    );
  `);
  const existing = db.prepare("SELECT schema_version FROM archive_meta WHERE singleton = 1").get();
  if (!existing) db.prepare("INSERT INTO archive_meta(singleton, schema_version, state) VALUES(1, ?, 'indexing')").run(DATABASE_SCHEMA_VERSION);
  else if (Number(existing.schema_version) !== DATABASE_SCHEMA_VERSION) throw new Error("unsupported archive cache schema");
  return db;
}

export function readDatabaseMeta(db: DatabaseSync): DatabaseMeta {
  const row = db.prepare("SELECT state, epoch_id, revision, last_attempt_at, last_success_at, last_error_category, last_error_count, schema_version FROM archive_meta WHERE singleton=1").get();
  if (!row) throw new Error("archive cache metadata is missing");
  return {
    state: String(row.state), epochId: row.epoch_id == null ? null : String(row.epoch_id), revision: Number(row.revision),
    lastAttemptAt: row.last_attempt_at == null ? null : String(row.last_attempt_at), lastSuccessAt: row.last_success_at == null ? null : String(row.last_success_at),
    lastErrorCategory: row.last_error_category == null ? null : String(row.last_error_category), lastErrorCount: Number(row.last_error_count), schemaVersion: Number(row.schema_version),
  };
}

export function updateDatabaseMeta(db: DatabaseSync, patch: Partial<DatabaseMeta> & { watchState?: string; lastScanDurationMs?: number | null }) {
  const fields: string[] = [];
  const values: unknown[] = [];
  const map: Record<string, unknown> = { state: patch.state, epoch_id: patch.epochId, revision: patch.revision, last_attempt_at: patch.lastAttemptAt, last_success_at: patch.lastSuccessAt, last_error_category: patch.lastErrorCategory, last_error_count: patch.lastErrorCount, schema_version: patch.schemaVersion, watch_state: patch.watchState, last_scan_duration_ms: patch.lastScanDurationMs };
  for (const [key, value] of Object.entries(map)) if (value !== undefined) { fields.push(`${key} = ?`); values.push(value); }
  if (fields.length) db.prepare(`UPDATE archive_meta SET ${fields.join(", ")} WHERE singleton=1`).run(...values);
}

export function withTransaction<T>(db: DatabaseSync, fn: () => T): T {
  db.exec("BEGIN IMMEDIATE");
  try { const result = fn(); db.exec("COMMIT"); return result; } catch (error) { try { db.exec("ROLLBACK"); } catch { /* preserve original failure */ } throw error; }
}

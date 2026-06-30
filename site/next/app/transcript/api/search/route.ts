import { existsSync } from 'node:fs';
import path from 'node:path';

import type { NextRequest } from 'next/server';

export const dynamic = 'force-dynamic';
export const runtime = 'nodejs';

type SessionRow = {
  id: string;
  filename: string;
  archive_member: string;
  bytes: number;
  compressed_bytes: number;
  modified_at: string;
  host: string;
  started_at: string;
  session_id: string;
  cwd: string;
  originator: string;
  source: string;
  cli_version: string;
  model_provider: string;
  model: string;
  lines: number;
  message_count: number;
  user_messages: number;
  assistant_messages: number;
  developer_messages: number;
  event_count: number;
  tool_calls: number;
  compacted_count: number;
  total_tokens: number;
  title: string;
  preview: string;
  samples_json: string;
};

type CountRow = {
  total: number;
};

type SummaryRow = {
  transcript_count: number | null;
  total_tool_calls: number | null;
  total_tokens: number | null;
  date_start: string | null;
  date_end: string | null;
};

type MetadataRow = {
  value: string;
};

type TranscriptDatabase = {
  prepare(query: string): {
    all(...params: unknown[]): unknown[];
    get(...params: unknown[]): unknown;
  };
  close(): void;
};

const pageSize = 25;
const sqlitePathCandidates = [
  path.join(process.cwd(), '.generated', 'transcripts', 'transcripts.sqlite'),
  path.join(process.cwd(), 'site', 'next', '.generated', 'transcripts', 'transcripts.sqlite'),
  path.join(process.cwd(), '.next', 'standalone', '.generated', 'transcripts', 'transcripts.sqlite'),
  path.join('/opt', 'coquic-demo', 'dataset', 'transcripts.sqlite'),
];

export async function GET(request: NextRequest) {
  const sqlitePath = resolveSqlitePath();
  if (!sqlitePath) {
    return Response.json({ detail: 'Transcript database unavailable' }, { status: 503 });
  }

  const searchParams = request.nextUrl.searchParams;
  const query = searchParams.get('q')?.trim() ?? '';
  const dateRange = parseDateRange(searchParams.get('from'), searchParams.get('to'));
  const page = clampNumber(searchParams.get('page'), 1, 1, 10_000);

  try {
    const db = await openDatabase(sqlitePath);
    try {
      const manifest = readManifest(db);
      const total = countSessions(db, query, dateRange);
      const totalPages = Math.max(1, Math.ceil(total / pageSize));
      const boundedPage = Math.min(page, totalPages);
      const offset = (boundedPage - 1) * pageSize;
      const sessions = query
        ? searchSessions(db, query, dateRange, pageSize, offset)
        : listSessions(db, dateRange, pageSize, offset);
      const summary = summarizeSessions(db, query, dateRange);

      return Response.json({
        manifest: {
          ...manifest,
          archiveUrl: process.env.COQUIC_TRANSCRIPT_ARCHIVE_URL || manifest.archiveUrl,
          transcriptCount: summary.transcript_count ?? 0,
          totalToolCalls: summary.total_tool_calls ?? 0,
          totalTokens: summary.total_tokens ?? 0,
          dateRange:
            summary.date_start && summary.date_end
              ? {
                  start: summary.date_start,
                  end: summary.date_end,
                }
              : undefined,
        },
        query,
        from: dateRange.fromDate,
        to: dateRange.toDate,
        page: boundedPage,
        pageSize,
        total,
        totalPages,
        sessions: sessions.map(sessionFromRow),
      });
    } finally {
      db.close();
    }
  } catch (error) {
    console.error('Transcript query failed', error);
    return Response.json({ detail: 'Transcript query failed' }, { status: 500 });
  }
}

function resolveSqlitePath() {
  const configured = process.env.COQUIC_TRANSCRIPT_SQLITE_PATH;
  if (configured && existsSync(configured)) return configured;
  return sqlitePathCandidates.find((candidate) => existsSync(candidate)) ?? '';
}

async function openDatabase(sqlitePath: string) {
  const sqlite = (process as NodeJS.Process & { getBuiltinModule?: (id: string) => unknown }).getBuiltinModule?.('node:sqlite') as
    | { DatabaseSync: new (filename: string, options: { readOnly: true }) => TranscriptDatabase }
    | undefined;
  if (!sqlite) throw new Error('node:sqlite is unavailable');
  return new sqlite.DatabaseSync(sqlitePath, { readOnly: true });
}

function readManifest(db: TranscriptDatabase) {
  const row = db.prepare('SELECT value FROM metadata WHERE key = ?').get('manifest') as MetadataRow | undefined;
  if (!row) throw new Error('missing transcript manifest metadata');
  return JSON.parse(row.value);
}

function countSessions(db: TranscriptDatabase, query: string, dateRange: DateRangeFilter) {
  const filter = sessionFilterSql(query, dateRange);
  const row = db
    .prepare(`SELECT COUNT(*) AS total FROM sessions WHERE ${filter.sql}`)
    .get(...filter.params) as CountRow;
  return row.total;
}

function summarizeSessions(db: TranscriptDatabase, query: string, dateRange: DateRangeFilter) {
  const filter = sessionFilterSql(query, dateRange);
  return db
    .prepare(
      `
        SELECT
          COUNT(*) AS transcript_count,
          COALESCE(SUM(tool_calls), 0) AS total_tool_calls,
          COALESCE(SUM(total_tokens), 0) AS total_tokens,
          MIN(started_at) AS date_start,
          MAX(started_at) AS date_end
        FROM sessions
        WHERE ${filter.sql}
      `,
    )
    .get(...filter.params) as SummaryRow;
}

function listSessions(db: TranscriptDatabase, dateRange: DateRangeFilter, limit: number, offset: number) {
  const filter = sessionFilterSql('', dateRange);
  return db
    .prepare(
      `
        SELECT *
        FROM sessions
        WHERE ${filter.sql}
        ORDER BY started_at DESC, bytes DESC
        LIMIT ? OFFSET ?
      `,
    )
    .all(...filter.params, limit, offset) as SessionRow[];
}

function searchSessions(db: TranscriptDatabase, query: string, dateRange: DateRangeFilter, limit: number, offset: number) {
  const filter = sessionFilterSql(query, dateRange);
  return db
    .prepare(
      `
        SELECT *
        FROM sessions
        WHERE ${filter.sql}
        ORDER BY started_at DESC, bytes DESC
        LIMIT ? OFFSET ?
      `,
    )
    .all(...filter.params, limit, offset) as SessionRow[];
}

function sessionFilterSql(query: string, dateRange: DateRangeFilter) {
  const clauses = ['started_at >= ?', 'started_at < ?'];
  const params = [dateRange.fromIso, dateRange.toExclusiveIso];
  if (!query) {
    return { sql: clauses.join(' AND '), params };
  }
  clauses.push(metadataSearchSql());
  params.push(...metadataSearchParams(query));
  return { sql: clauses.join(' AND '), params };
}

function sessionFromRow(row: SessionRow) {
  return {
    id: row.id,
    filename: row.filename,
    archiveMember: row.archive_member,
    bytes: row.bytes,
    compressedBytes: row.compressed_bytes,
    modifiedAt: row.modified_at,
    host: row.host,
    startedAt: row.started_at,
    sessionId: row.session_id,
    cwd: row.cwd,
    originator: row.originator,
    source: row.source,
    cliVersion: row.cli_version,
    modelProvider: row.model_provider,
    model: row.model,
    lines: row.lines,
    messageCount: row.message_count,
    userMessages: row.user_messages,
    assistantMessages: row.assistant_messages,
    developerMessages: row.developer_messages,
    eventCount: row.event_count,
    toolCalls: row.tool_calls,
    compactedCount: row.compacted_count,
    totalTokens: row.total_tokens,
    title: row.title,
    preview: row.preview,
    samples: JSON.parse(row.samples_json),
  };
}

type DateRangeFilter = {
  fromDate: string;
  fromIso: string;
  toDate: string;
  toExclusiveIso: string;
};

function parseDateRange(fromValue: string | null, toValue: string | null): DateRangeFilter {
  const normalizedFrom = normalizeDateParam(fromValue);
  const normalizedTo = normalizeDateParam(toValue);
  const fallbackFrom = '0001-01-01';
  if (!normalizedFrom && !normalizedTo) {
    return {
      fromDate: '',
      fromIso: `${fallbackFrom}T00:00:00.000Z`,
      toDate: '',
      toExclusiveIso: '9999-12-31T23:59:59.999Z',
    };
  }
  const rawFrom = normalizedFrom || fallbackFrom;
  const rawTo = normalizedTo || '9999-12-31';
  const orderedFrom = rawFrom <= rawTo ? rawFrom : rawTo;
  const orderedTo = rawFrom <= rawTo ? rawTo : rawFrom;
  if (orderedTo === '9999-12-31' && !normalizedTo) {
    return {
      fromDate: orderedFrom === fallbackFrom ? '' : orderedFrom,
      fromIso: `${orderedFrom}T00:00:00.000Z`,
      toDate: '',
      toExclusiveIso: '9999-12-31T23:59:59.999Z',
    };
  }
  const toExclusive = new Date(`${orderedTo}T00:00:00.000Z`);
  toExclusive.setUTCDate(toExclusive.getUTCDate() + 1);
  return {
    fromDate: orderedFrom === fallbackFrom ? '' : orderedFrom,
    fromIso: `${orderedFrom}T00:00:00.000Z`,
    toDate: orderedTo,
    toExclusiveIso: toExclusive.toISOString(),
  };
}

function normalizeDateParam(value: string | null) {
  if (!value || !/^\d{4}-\d{2}-\d{2}$/.test(value)) return '';
  const date = new Date(`${value}T00:00:00.000Z`);
  if (Number.isNaN(date.getTime())) return '';
  return date.toISOString().slice(0, 10);
}

function metadataSearchSql() {
  return `
    (
      title LIKE ? ESCAPE '\\' OR
      preview LIKE ? ESCAPE '\\' OR
      filename LIKE ? ESCAPE '\\' OR
      session_id LIKE ? ESCAPE '\\' OR
      host LIKE ? ESCAPE '\\' OR
      cwd LIKE ? ESCAPE '\\' OR
      originator LIKE ? ESCAPE '\\' OR
      source LIKE ? ESCAPE '\\' OR
      model LIKE ? ESCAPE '\\' OR
      model_provider LIKE ? ESCAPE '\\'
    )
  `;
}

function metadataSearchParams(query: string) {
  const pattern = `%${query.replace(/[\\%_]/g, (match) => `\\${match}`)}%`;
  return Array.from({ length: 10 }, () => pattern);
}

function clampNumber(value: string | null, fallback: number, min: number, max: number) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(max, Math.max(min, Math.trunc(parsed)));
}

import { existsSync } from 'node:fs';
import path from 'node:path';
import readline from 'node:readline';
import yauzl from 'yauzl';

import { parseCodexTranscriptLine, type TranscriptRecord } from '@/lib/codex-transcript';
import type { NextRequest } from 'next/server';

export const dynamic = 'force-dynamic';
export const runtime = 'nodejs';

type RouteContext = {
  params: Promise<{
    sessionId: string;
  }>;
};

type SessionRow = {
  id: string;
  archive_member: string;
  bytes: number;
  lines: number;
};

type ParsedJsonl = {
  records: TranscriptRecord[];
  hasMore: boolean;
  nextCursor: number;
  scannedLines: number;
  scanLimited: boolean;
};

type TranscriptDatabase = {
  prepare(query: string): {
    get(...params: unknown[]): unknown;
  };
  close(): void;
};

const sqlitePathCandidates = [
  path.join(process.cwd(), '.generated', 'transcripts', 'transcripts.sqlite'),
  path.join(process.cwd(), 'site', 'next', '.generated', 'transcripts', 'transcripts.sqlite'),
  path.join(process.cwd(), '.next', 'standalone', '.generated', 'transcripts', 'transcripts.sqlite'),
  path.join('/opt', 'coquic-demo', 'dataset', 'transcripts.sqlite'),
];
const archivePathCandidates = [
  path.join(process.cwd(), 'public', 'dataset', 'codex-history-coquic-transcripts-only-20260630.zip'),
  path.join(process.cwd(), 'site', 'next', 'public', 'dataset', 'codex-history-coquic-transcripts-only-20260630.zip'),
  path.join(process.cwd(), '.next', 'standalone', 'public', 'dataset', 'codex-history-coquic-transcripts-only-20260630.zip'),
  path.join('/opt', 'coquic-demo', 'dataset', 'codex-history-coquic-transcripts-only-20260630.zip'),
];
const defaultLimit = 80;
const maxLimit = 140;
const maxParseLineBytes = 2 * 1024 * 1024;
const maxRecordTextLength = 60_000;
const maxScannedLinesPerRequest = 20_000;

export async function GET(request: NextRequest, context: RouteContext) {
  const sqlitePath = resolvePath(process.env.COQUIC_TRANSCRIPT_SQLITE_PATH, sqlitePathCandidates);
  const archivePath = resolvePath(process.env.COQUIC_TRANSCRIPT_ARCHIVE_PATH, archivePathCandidates);
  if (!sqlitePath || !archivePath) {
    return Response.json({ detail: 'Transcript source unavailable' }, { status: 503 });
  }

  const { sessionId } = await context.params;
  const session = await findSession(sqlitePath, decodeURIComponent(sessionId));
  if (!session) {
    return Response.json({ detail: 'Transcript session not found' }, { status: 404 });
  }

  const cursor = clampNumber(request.nextUrl.searchParams.get('cursor'), 0, 0, Number.MAX_SAFE_INTEGER);
  const limit = clampNumber(request.nextUrl.searchParams.get('limit'), defaultLimit, 1, maxLimit);

  try {
    const parsed = await parseZipMember(archivePath, session.archive_member, { cursor, limit, totalLines: session.lines });
    return Response.json({
      sessionId: session.id,
      archiveMember: session.archive_member,
      bytes: session.bytes,
      totalLines: session.lines,
      records: parsed.records,
      hasMore: parsed.hasMore,
      nextCursor: parsed.nextCursor,
      scannedLines: parsed.scannedLines,
      scanLimited: parsed.scanLimited,
      limit,
    });
  } catch (_error) {
    return Response.json({ detail: 'Transcript JSONL unavailable' }, { status: 500 });
  }
}

function resolvePath(configured: string | undefined, candidates: string[]) {
  if (configured && existsSync(configured)) return configured;
  return candidates.find((candidate) => existsSync(candidate)) ?? '';
}

async function openDatabase(sqlitePath: string) {
  const sqlite = (process as NodeJS.Process & { getBuiltinModule?: (id: string) => unknown }).getBuiltinModule?.('node:sqlite') as
    | { DatabaseSync: new (filename: string, options: { readOnly: true }) => TranscriptDatabase }
    | undefined;
  if (!sqlite) throw new Error('node:sqlite is unavailable');
  return new sqlite.DatabaseSync(sqlitePath, { readOnly: true });
}

async function findSession(sqlitePath: string, sessionId: string) {
  const db: TranscriptDatabase = await openDatabase(sqlitePath);
  try {
    return db
      .prepare('SELECT id, archive_member, bytes, lines FROM sessions WHERE id = ? OR session_id = ?')
      .get(sessionId, sessionId) as SessionRow | undefined;
  } finally {
    db.close();
  }
}

function parseZipMember(zipPath: string, memberName: string, options: { cursor: number; limit: number; totalLines: number }) {
  return new Promise<ParsedJsonl>((resolve, reject) => {
    yauzl.open(zipPath, { lazyEntries: true }, (openError, zipFile) => {
      if (openError || !zipFile) {
        reject(openError ?? new Error('failed to open transcript archive'));
        return;
      }

      zipFile.readEntry();
      zipFile.on('entry', (entry) => {
        if (entry.fileName !== memberName) {
          zipFile.readEntry();
          return;
        }
        zipFile.openReadStream(entry, (streamError, stream) => {
          if (streamError || !stream) {
            zipFile.close();
            reject(streamError ?? new Error(`failed to read ${memberName}`));
            return;
          }
          parseJsonlStream(stream, options)
            .then((parsed) => {
              zipFile.close();
              resolve(parsed);
            })
            .catch((error: unknown) => {
              zipFile.close();
              reject(error);
            });
        });
      });
      zipFile.on('end', () => {
        reject(new Error(`missing archive member: ${memberName}`));
      });
      zipFile.on('error', reject);
    });
  });
}

async function parseJsonlStream(stream: NodeJS.ReadableStream, { cursor, limit, totalLines }: { cursor: number; limit: number; totalLines: number }): Promise<ParsedJsonl> {
  const records: TranscriptRecord[] = [];
  const lines = readline.createInterface({ input: stream, crlfDelay: Infinity });
  let lineCount = 0;
  let hasMore = false;
  let scanLimited = false;
  let stopEarly = false;

  for await (const line of lines) {
    if (!line.trim()) continue;
    lineCount += 1;
    if (lineCount <= cursor) continue;
    if (lineCount - cursor > maxScannedLinesPerRequest) {
      hasMore = totalLines ? lineCount < totalLines : true;
      scanLimited = true;
      stopEarly = true;
      lines.close();
      break;
    }

    const parsedRecords = parseCodexTranscriptLine(line, lineCount, { maxParseLineBytes, maxRecordTextLength });
    if (!parsedRecords.length) continue;

    for (const record of parsedRecords) {
      records.push(record);
      if (records.length >= limit) break;
    }
    if (records.length >= limit) {
      hasMore = totalLines ? lineCount < totalLines : true;
      stopEarly = true;
      lines.close();
      break;
    }
  }

  if (stopEarly && 'destroy' in stream && typeof stream.destroy === 'function') {
    stream.destroy();
  }

  return {
    records,
    hasMore,
    nextCursor: records.at(-1)?.line ?? lineCount,
    scannedLines: lineCount,
    scanLimited,
  };
}

function clampNumber(value: string | null, fallback: number, min: number, max: number) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(max, Math.max(min, Math.trunc(parsed)));
}

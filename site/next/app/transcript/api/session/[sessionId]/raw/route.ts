import { existsSync } from 'node:fs';
import path from 'node:path';
import { Readable } from 'node:stream';
import yauzl from 'yauzl';

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

export async function GET(_request: NextRequest, context: RouteContext) {
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

  try {
    const stream = await openZipMember(archivePath, session.archive_member);
    const filename = path.basename(session.archive_member);
    return new Response(Readable.toWeb(stream) as ReadableStream, {
      headers: {
        'Content-Disposition': `attachment; filename="${filename}"`,
        'Content-Type': 'application/x-ndjson; charset=utf-8',
      },
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
      .prepare('SELECT id, archive_member FROM sessions WHERE id = ? OR session_id = ?')
      .get(sessionId, sessionId) as SessionRow | undefined;
  } finally {
    db.close();
  }
}

function openZipMember(zipPath: string, memberName: string) {
  return new Promise<Readable>((resolve, reject) => {
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
          stream.once('end', () => {
            zipFile.close();
          });
          stream.once('error', () => {
            zipFile.close();
          });
          resolve(stream);
        });
      });
      zipFile.on('end', () => {
        reject(new Error(`missing archive member: ${memberName}`));
      });
      zipFile.on('error', reject);
    });
  });
}

import { createReadStream, existsSync, statSync } from 'node:fs';
import path from 'node:path';
import { Readable } from 'node:stream';

import type { NextRequest } from 'next/server';

export const dynamic = 'force-dynamic';
export const runtime = 'nodejs';

type RouteContext = {
  params: Promise<{
    filename: string;
  }>;
};

const defaultArchiveName = 'codex-history-coquic-transcripts-only-20260630.zip';

export async function GET(_request: NextRequest, context: RouteContext) {
  return serveDatasetArchive(context, true);
}

export async function HEAD(_request: NextRequest, context: RouteContext) {
  return serveDatasetArchive(context, false);
}

async function serveDatasetArchive(context: RouteContext, includeBody: boolean) {
  const { filename } = await context.params;
  if (!isSafeFilename(filename)) {
    return Response.json({ detail: 'Dataset archive not found' }, { status: 404 });
  }

  const archivePath = resolveArchivePath(filename);
  if (!archivePath) {
    return Response.json({ detail: 'Dataset archive unavailable' }, { status: 404 });
  }

  const stats = statSync(archivePath);
  const headers = {
    'Cache-Control': 'public, max-age=3600',
    'Content-Disposition': `attachment; filename="${filename}"`,
    'Content-Length': String(stats.size),
    'Content-Type': 'application/zip',
  };

  if (!includeBody) {
    return new Response(null, { headers });
  }

  const stream = createReadStream(archivePath);
  return new Response(Readable.toWeb(stream) as ReadableStream, { headers });
}

function resolveArchivePath(filename: string) {
  const configured = process.env.COQUIC_TRANSCRIPT_ARCHIVE_PATH;
  if (configured && path.basename(configured) === filename && existsSync(configured)) return configured;

  const defaultArchivePath = `/opt/coquic-demo/dataset/${filename}`;
  return existsSync(defaultArchivePath) ? defaultArchivePath : '';
}

function isSafeFilename(filename: string) {
  if (!/^[A-Za-z0-9._-]+$/.test(filename)) return false;
  return filename === defaultArchiveName || path.basename(process.env.COQUIC_TRANSCRIPT_ARCHIVE_PATH ?? '') === filename;
}

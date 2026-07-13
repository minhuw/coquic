import { readFile } from 'node:fs/promises';
import path from 'node:path';

import { stewardNdjsonHeaders, stewardNotFoundResponse } from '../../../../../../route-headers';

export const dynamic = 'force-dynamic';
export const runtime = 'nodejs';

type RouteContext = {
  params: Promise<{
    runName: string;
    taskId: string;
  }>;
};

const publicSegmentPattern = /^[A-Za-z0-9._-]+$/;
const taskIdPattern = /^task-\d{14}-[a-f0-9]{8}$/;

function isWithin(parent: string, child: string): boolean {
  const relative = path.relative(parent, child);
  return relative !== ''
    && relative !== '..'
    && !relative.startsWith(`..${path.sep}`)
    && !path.isAbsolute(relative);
}

function resolvePublicArtifactPath(siteRoot: string, taskId: string, runName: string): string | null {
  if (runName === '.' || runName === '..') return null;

  const runsDirectory = path.resolve(
    siteRoot,
    'public',
    'steward',
    'data',
    'tasks',
    taskId,
    'runs',
  );
  const runDirectory = path.resolve(runsDirectory, runName);
  const artifactPath = path.resolve(runDirectory, 'codex.jsonl');
  if (!isWithin(runsDirectory, runDirectory) || !isWithin(runDirectory, artifactPath)) {
    return null;
  }
  return artifactPath;
}

export async function GET(_request: Request, context: RouteContext) {
  const { runName, taskId } = await context.params;
  if (!taskIdPattern.test(taskId) || !publicSegmentPattern.test(runName)) {
    return stewardNotFoundResponse();
  }

  const filePath = resolvePublicArtifactPath(
    process.env.COQUIC_STEWARD_PUBLIC_ROOT ?? process.cwd(),
    taskId,
    runName,
  );
  if (!filePath) return stewardNotFoundResponse();

  try {
    const body = await readFile(filePath);
    return new Response(body, {
      headers: stewardNdjsonHeaders,
    });
  } catch {
    return stewardNotFoundResponse();
  }
}

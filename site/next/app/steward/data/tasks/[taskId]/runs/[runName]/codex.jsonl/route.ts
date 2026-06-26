import { readFile } from 'node:fs/promises';
import path from 'node:path';

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

export async function GET(_request: Request, context: RouteContext) {
  const { runName, taskId } = await context.params;
  if (!taskIdPattern.test(taskId) || !publicSegmentPattern.test(runName)) {
    return Response.json({ detail: 'not found' }, { status: 404 });
  }

  const filePath = path.join(
    process.cwd(),
    'public',
    'steward',
    'data',
    'tasks',
    taskId,
    'runs',
    runName,
    'codex.jsonl',
  );

  try {
    const body = await readFile(filePath);
    return new Response(body, {
      headers: {
        'cache-control': 'public, max-age=0',
        'content-type': 'application/x-ndjson; charset=UTF-8',
      },
    });
  } catch {
    return Response.json({ detail: 'not found' }, { status: 404 });
  }
}

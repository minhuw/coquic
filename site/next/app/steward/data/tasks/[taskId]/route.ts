import { readFile } from 'node:fs/promises';
import path from 'node:path';

export const dynamic = 'force-dynamic';
export const runtime = 'nodejs';

type RouteContext = {
  params: Promise<{
    taskId: string;
  }>;
};

const taskDetailFilePattern = /^task-\d{14}-[a-f0-9]{8}\.json$/;

export async function GET(_request: Request, context: RouteContext) {
  const { taskId } = await context.params;
  if (taskId !== 'index.json' && !taskDetailFilePattern.test(taskId)) {
    return Response.json({ detail: 'not found' }, { status: 404 });
  }

  const filePath = path.join(
    process.cwd(),
    'public',
    'steward',
    'data',
    'tasks',
    taskId,
  );

  try {
    const body = await readFile(filePath);
    return new Response(body, {
      headers: {
        'cache-control': 'public, max-age=0',
        'content-type': 'application/json; charset=UTF-8',
      },
    });
  } catch {
    return Response.json({ detail: 'not found' }, { status: 404 });
  }
}

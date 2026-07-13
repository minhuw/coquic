import { readFile } from 'node:fs/promises';
import path from 'node:path';

import { stewardJsonHeaders, stewardNotFoundResponse } from '../../../route-headers';

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
    return stewardNotFoundResponse();
  }

  const filePath = path.join(
    process.env.COQUIC_STEWARD_PUBLIC_ROOT ?? process.cwd(),
    'public',
    'steward',
    'data',
    'tasks',
    taskId,
  );

  try {
    const body = await readFile(filePath);
    return new Response(body, {
      headers: stewardJsonHeaders,
    });
  } catch {
    return stewardNotFoundResponse();
  }
}

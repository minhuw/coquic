import { readPublicStewardStatus } from './status-route';

export const dynamic = 'force-dynamic';
export const runtime = 'nodejs';

const noStoreHeaders = { 'Cache-Control': 'no-store' };

export async function GET() {
  const result = await readPublicStewardStatus(process.cwd());
  if (result.status === 'unavailable') {
    return Response.json(result, { status: 503, headers: noStoreHeaders });
  }

  return Response.json(result.data, { headers: noStoreHeaders });
}

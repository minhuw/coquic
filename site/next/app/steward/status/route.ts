import { readPublicStewardStatus } from './status-route';
import { stewardJsonHeaders } from '../route-headers';

export const dynamic = 'force-dynamic';
export const runtime = 'nodejs';

export async function GET() {
  const result = await readPublicStewardStatus(
    process.env.COQUIC_STEWARD_PUBLIC_ROOT ?? process.cwd(),
  );
  if (result.status === 'unavailable') {
    return Response.json(result, { headers: stewardJsonHeaders, status: 503 });
  }

  return Response.json(result.data, { headers: stewardJsonHeaders });
}

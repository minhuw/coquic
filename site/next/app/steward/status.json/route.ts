import { stewardRedirectHeaders } from '../route-headers';

export const dynamic = 'force-dynamic';
export const runtime = 'nodejs';

export function GET() {
  return new Response(null, {
    headers: {
      ...stewardRedirectHeaders,
      Location: '/steward/status',
    },
    status: 308,
  });
}

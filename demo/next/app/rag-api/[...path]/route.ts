import { type NextRequest } from 'next/server';

export const dynamic = 'force-dynamic';
export const runtime = 'nodejs';

type RouteContext = {
  params: Promise<{
    path: string[];
  }>;
};

const defaultRagApiBase = 'http://127.0.0.1:8787';

export async function GET(request: NextRequest, context: RouteContext) {
  return proxyRequest(request, context);
}

export async function POST(request: NextRequest, context: RouteContext) {
  return proxyRequest(request, context);
}

async function proxyRequest(request: NextRequest, context: RouteContext) {
  const params = await context.params;
  const upstream = upstreamUrl(params.path, request.nextUrl.search);
  const headers = upstreamHeaders(request);
  const init: RequestInit = {
    method: request.method,
    headers,
    cache: 'no-store',
    signal: AbortSignal.timeout(120_000),
  };

  if (request.method !== 'GET' && request.method !== 'HEAD') {
    init.body = await request.arrayBuffer();
  }

  try {
    const response = await fetch(upstream, init);
    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: responseHeaders(response.headers),
    });
  } catch (_error) {
    return Response.json({ detail: 'RAG API unavailable' }, { status: 503 });
  }
}

function upstreamUrl(path: string[], search: string) {
  const base = process.env.COQUIC_RAG_API_BASE || defaultRagApiBase;
  const normalizedBase = base.endsWith('/') ? base : `${base}/`;
  const encodedPath = path.map((segment) => encodeURIComponent(segment)).join('/');
  return new URL(`${encodedPath}${search}`, normalizedBase);
}

function upstreamHeaders(request: NextRequest) {
  const headers = new Headers();
  copyHeader(request, headers, 'accept');
  copyHeader(request, headers, 'content-type');
  copyHeader(request, headers, 'user-agent');
  copyHeader(request, headers, 'x-session-id');

  const forwardedFor = request.headers.get('x-forwarded-for');
  if (forwardedFor) {
    headers.set('x-forwarded-for', forwardedFor);
  }
  return headers;
}

function responseHeaders(upstream: Headers) {
  const headers = new Headers();
  copyResponseHeader(upstream, headers, 'cache-control');
  copyResponseHeader(upstream, headers, 'content-type');
  copyResponseHeader(upstream, headers, 'retry-after');
  return headers;
}

function copyHeader(request: NextRequest, headers: Headers, name: string) {
  const value = request.headers.get(name);
  if (value) {
    headers.set(name, value);
  }
}

function copyResponseHeader(source: Headers, target: Headers, name: string) {
  const value = source.get(name);
  if (value) {
    target.set(name, value);
  }
}

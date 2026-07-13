export const stewardJsonHeaders = {
  'Cache-Control': 'no-store',
  'Content-Type': 'application/json; charset=utf-8',
  'X-Content-Type-Options': 'nosniff',
};

export const stewardNdjsonHeaders = {
  'Cache-Control': 'no-store',
  'Content-Type': 'application/x-ndjson; charset=utf-8',
  'X-Content-Type-Options': 'nosniff',
};

export const stewardRedirectHeaders = {
  'Cache-Control': 'no-store',
  'X-Content-Type-Options': 'nosniff',
};

export function stewardNotFoundResponse(): Response {
  return Response.json(
    { detail: 'not found' },
    { headers: stewardJsonHeaders, status: 404 },
  );
}

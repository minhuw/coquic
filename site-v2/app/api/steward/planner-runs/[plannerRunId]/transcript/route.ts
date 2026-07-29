import { serializeCloudProblem } from "@/lib/steward-archive/cloud-schema";

export const dynamic = "force-dynamic";
export const revalidate = 0;

const RESPONSE_HEADERS = {
  "Cache-Control": "no-store",
  "Content-Type": "application/json; charset=utf-8",
  "X-Content-Type-Options": "nosniff",
} as const;

const UNAVAILABLE_PROBLEM = {
  code: "UNAVAILABLE",
  message: "The global archive domain is unavailable in the cloud contract.",
  retryable: false,
  status: 410,
  type: null,
} as const;

function unavailableResponse(): Response {
  return new Response(serializeCloudProblem({
    schemaVersion: "3.0",
    generatedAt: new Date().toISOString(),
    problem: UNAVAILABLE_PROBLEM,
  }), { status: 410, headers: RESPONSE_HEADERS });
}

export async function GET(_request: Request, _context: { params: Promise<{ plannerRunId: string }> }) {
  return unavailableResponse();
}

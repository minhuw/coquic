import { NextResponse } from "next/server";
import { CloudReaderConfigError } from "@/lib/steward-archive/cloud-config";
import { CloudflareD1Error } from "@/lib/steward-archive/cloudflare";
import {
  CloudRepositoryDataError,
  getCloudRepository,
  PublicationCursorError,
} from "@/lib/steward-archive/cloud-repository";
import { serializeCloudProblem, serializeCloudStatus } from "@/lib/steward-archive/cloud-schema";

export const dynamic = "force-dynamic";
export const revalidate = 0;

type Problem = {
  readonly code: string;
  readonly status: number;
  readonly message: string;
  readonly retryable: boolean;
};

function response(body: string, status: number): NextResponse {
  return new NextResponse(body, {
    status,
    headers: {
      "Cache-Control": "no-store",
      "Content-Type": "application/json; charset=utf-8",
    },
  });
}

function problemResponse(problem: Problem): NextResponse {
  const body = serializeCloudProblem({
    schemaVersion: "3.0",
    generatedAt: new Date().toISOString(),
    problem: {
      code: problem.code,
      message: problem.message,
      retryable: problem.retryable,
      status: problem.status,
      type: null,
    },
  });
  return response(body, problem.status);
}

function mapError(error: unknown): Problem {
  if (error instanceof PublicationCursorError) {
    return error.code === "STALE_CURSOR"
      ? { code: "STALE_CURSOR", status: 409, message: "The requested cloud page cursor is stale.", retryable: false }
      : { code: "INVALID_CURSOR", status: 400, message: "The requested cloud page cursor is invalid.", retryable: false };
  }
  if (error instanceof CloudReaderConfigError) {
    return { code: "MISCONFIGURED", status: 503, message: "Steward cloud access is not configured.", retryable: false };
  }
  if (error instanceof CloudRepositoryDataError) {
    return { code: "INTEGRITY_FAILURE", status: 503, message: "Steward cloud data failed validation.", retryable: false };
  }
  if (error instanceof CloudflareD1Error) {
    return error.code === "rate-limited"
      ? { code: "RATE_LIMITED", status: 429, message: "Steward cloud access is rate limited.", retryable: true }
      : { code: "UNAVAILABLE", status: 503, message: "Steward cloud data is temporarily unavailable.", retryable: true };
  }
  return { code: "UNAVAILABLE", status: 503, message: "Steward cloud data is temporarily unavailable.", retryable: true };
}

export async function GET() {
  try {
    const status = await getCloudRepository().getStatus();
    return response(serializeCloudStatus({ schemaVersion: "3.0", generatedAt: new Date().toISOString(), data: status }), 200);
  } catch (error) {
    return problemResponse(mapError(error));
  }
}

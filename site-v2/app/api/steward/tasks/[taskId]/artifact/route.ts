import { CloudReaderConfigError } from "@/lib/steward-archive/cloud-config";
import { CloudflareD1Error } from "@/lib/steward-archive/cloudflare";
import {
  CloudRepositoryDataError,
  getCloudRepository,
} from "@/lib/steward-archive/cloud-repository";
import { serializeCloudProblem } from "@/lib/steward-archive/cloud-schema";

export const dynamic = "force-dynamic";
export const revalidate = 0;

const ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;

type Problem = {
  readonly code: string;
  readonly status: number;
  readonly message: string;
  readonly retryable: boolean;
};

class InvalidRequestError extends Error {}

function response(body: string, status: number): Response {
  return new Response(body, {
    status,
    headers: {
      "Cache-Control": "no-store",
      "Content-Type": "application/json; charset=utf-8",
    },
  });
}

function problemResponse(problem: Problem): Response {
  return response(serializeCloudProblem({
    schemaVersion: "3.0",
    generatedAt: new Date().toISOString(),
    problem: {
      code: problem.code,
      message: problem.message,
      retryable: problem.retryable,
      status: problem.status,
      type: null,
    },
  }), problem.status);
}

function mapError(error: unknown): Problem {
  if (error instanceof InvalidRequestError) {
    return { code: "INVALID_REQUEST", status: 400, message: "The cloud artifact request is invalid.", retryable: false };
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
      : {
        code: "UNAVAILABLE",
        status: 503,
        message: "Steward cloud data is temporarily unavailable.",
        retryable: error.code === "network-error" || error.code === "timeout" || error.code === "server-error",
      };
  }
  return { code: "UNAVAILABLE", status: 503, message: "Steward cloud data is temporarily unavailable.", retryable: false };
}

function parseTaskId(value: unknown): string {
  if (typeof value !== "string" || !ID.test(value)) throw new InvalidRequestError("invalid task id");
  return value;
}

function parseLogicalPath(value: string | null): string {
  if (value === null || value.length < 1 || value.length > 1024 || value.startsWith("/") || value.includes("\\") || value.includes("..") || value.includes("://") || [...value].some((character) => character.charCodeAt(0) < 0x20)) {
    throw new InvalidRequestError("invalid artifact path");
  }
  return value;
}

export async function GET(request: Request, context: { params: Promise<{ taskId: string }> }) {
  try {
    const { taskId: rawTaskId } = await context.params;
    const taskId = parseTaskId(rawTaskId);
    const path = parseLogicalPath(new URL(request.url).searchParams.get("path"));
    const artifact = await getCloudRepository().getArtifactDescriptor(taskId, path);
    if (!artifact || artifact.availability !== "available") {
      return problemResponse({ code: "NOT_FOUND", status: 404, message: "The selected artifact is not available.", retryable: false });
    }
    return new Response(null, {
      status: 307,
      headers: {
        "Cache-Control": "no-store",
        "Content-Type": "application/octet-stream",
        Location: artifact.publicUrl,
        "X-Content-Type-Options": "nosniff",
      },
    });
  } catch (error) {
    return problemResponse(mapError(error));
  }
}

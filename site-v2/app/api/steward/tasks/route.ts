import { NextResponse } from "next/server";
import { CloudReaderConfigError } from "@/lib/steward-archive/cloud-config";
import { CloudflareD1Error } from "@/lib/steward-archive/cloudflare";
import {
  CloudRepositoryDataError,
  getCloudRepository,
  PublicationCursorError,
  type CloudTaskScope,
} from "@/lib/steward-archive/cloud-repository";
import { serializeCloudProblem, serializeCloudTaskPage } from "@/lib/steward-archive/cloud-schema";

export const dynamic = "force-dynamic";
export const revalidate = 0;

const MAX_PAGE_SIZE = 50;

type Problem = {
  readonly code: string;
  readonly status: number;
  readonly message: string;
  readonly retryable: boolean;
};

class InvalidQueryError extends Error {}

function response(body: string, status: number, cursors?: { next: string | null; previous: string | null }): NextResponse {
  const headers = new Headers({
    "Cache-Control": "no-store",
    "Content-Type": "application/json; charset=utf-8",
  });
  if (cursors?.next) headers.set("X-Steward-Next-Cursor", cursors.next);
  if (cursors?.previous) headers.set("X-Steward-Previous-Cursor", cursors.previous);
  return new NextResponse(body, { status, headers });
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
  if (error instanceof InvalidQueryError) {
    return { code: "INVALID_REQUEST", status: 400, message: "The cloud task list request is invalid.", retryable: false };
  }
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
      : {
        code: "UNAVAILABLE",
        status: 503,
        message: "Steward cloud data is temporarily unavailable.",
        retryable: error.code === "network-error" || error.code === "timeout" || error.code === "server-error",
      };
  }
  return { code: "UNAVAILABLE", status: 503, message: "Steward cloud data is temporarily unavailable.", retryable: false };
}

function parseScope(value: string | null): CloudTaskScope {
  if (value === null || value === "history") return "history";
  if (value === "active") return "active";
  throw new InvalidQueryError("invalid task scope");
}

function parseLimit(value: string | null): number {
  if (value === null) return MAX_PAGE_SIZE;
  if (!/^-?\d+$/.test(value)) throw new InvalidQueryError("invalid task limit");
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed)) throw new InvalidQueryError("invalid task limit");
  return Math.min(MAX_PAGE_SIZE, Math.max(1, parsed));
}

function pageEnvelope(page: Awaited<ReturnType<ReturnType<typeof getCloudRepository>["listTasks"]>>, pageSize: number) {
  // Cloud cursors carry the position rather than a page number. The closed
  // response contract still needs a valid page value, so use the first page
  // while another page exists and the terminal page otherwise.
  const pageNumber = page.nextCursor === null ? Math.max(1, Math.ceil(page.total / pageSize)) : 1;
  return {
    schemaVersion: "3.0" as const,
    generatedAt: new Date().toISOString(),
    data: {
      items: [...page.tasks],
      pagination: {
        page: pageNumber,
        pageSize,
        total: page.total,
        hasNextPage: page.nextCursor !== null,
      },
    },
  };
}

export async function GET(request: Request) {
  try {
    const query = new URL(request.url).searchParams;
    const scope = parseScope(query.get("scope"));
    const cursor = query.get("cursor");
    const limit = parseLimit(query.get("limit"));
    const repository = getCloudRepository();
    const page = await repository.listTasks(scope, { cursor, limit });
    return response(serializeCloudTaskPage(pageEnvelope(page, limit)), 200, { next: page.nextCursor, previous: page.previousCursor });
  } catch (error) {
    return problemResponse(mapError(error));
  }
}

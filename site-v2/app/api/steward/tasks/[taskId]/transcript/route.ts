import { CloudReaderConfigError } from "@/lib/steward-archive/cloud-config";
import { CloudflareD1Error } from "@/lib/steward-archive/cloudflare";
import {
  CloudRepositoryDataError,
  getCloudRepository,
} from "@/lib/steward-archive/cloud-repository";
import { AtifLoaderError, loadVerifiedAtif } from "@/lib/steward-archive/atif-loader";
import { buildAtifViewModel } from "@/lib/steward-archive/atif-view-model";
import { serializeCloudCompleteTrajectory, serializeCloudProblem } from "@/lib/steward-archive/cloud-schema";

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
    return { code: "INVALID_REQUEST", status: 400, message: "The cloud transcript request is invalid.", retryable: false };
  }
  if (error instanceof AtifLoaderError) {
    if (error.category === "missing") {
      return { code: "NOT_FOUND", status: 404, message: "The selected transcript is not available.", retryable: false };
    }
    if (error.category === "resource") {
      return { code: "RESOURCE_LIMIT", status: 413, message: "The selected transcript exceeds the bounded resource limit.", retryable: false };
    }
    if (error.category === "integrity") {
      return { code: "INTEGRITY_FAILURE", status: 422, message: "The selected transcript failed public validation.", retryable: false };
    }
    return { code: "UNAVAILABLE", status: 503, message: "The selected transcript is temporarily unavailable.", retryable: true };
  }
  if (error instanceof CloudReaderConfigError) {
    return { code: "MISCONFIGURED", status: 503, message: "Steward cloud access is not configured.", retryable: false };
  }
  if (error instanceof CloudRepositoryDataError) {
    return { code: "INTEGRITY_FAILURE", status: 422, message: "Steward cloud data failed validation.", retryable: false };
  }
  if (error instanceof CloudflareD1Error) {
    if (error.code === "response-too-large" || error.code === "result-set-limit" || error.code === "row-limit") {
      return { code: "RESOURCE_LIMIT", status: 413, message: "Steward cloud data exceeds the bounded resource limit.", retryable: false };
    }
    if (error.code === "network-error" || error.code === "timeout" || error.code === "server-error" || error.code === "rate-limited") {
      return { code: "UNAVAILABLE", status: 503, message: "Steward cloud data is temporarily unavailable.", retryable: true };
    }
    return { code: "INTEGRITY_FAILURE", status: 422, message: "Steward cloud data failed public validation.", retryable: false };
  }
  return { code: "INTEGRITY_FAILURE", status: 422, message: "The selected transcript failed public validation.", retryable: false };
}

function parseTaskId(value: unknown): string {
  if (typeof value !== "string" || !ID.test(value)) throw new InvalidRequestError("invalid task id");
  return value;
}

function parseRunId(value: string | null): string | undefined {
  if (value === null) return undefined;
  if (!ID.test(value)) throw new InvalidRequestError("invalid run id");
  return value;
}

function resolveRunId(
  detail: Awaited<ReturnType<ReturnType<typeof getCloudRepository>["getTaskDetail"]>>,
  requestedRunId: string | undefined,
): string | null {
  if (!detail) return null;
  if (requestedRunId === undefined) return detail.trajectory?.runId ?? null;
  const run = detail.runs.find((candidate) => candidate.runId === requestedRunId);
  if (!run || run.runState !== "completed") return null;
  const atif = detail.artifacts.some((artifact) => artifact.runId === requestedRunId
    && artifact.mediaType === "application/json"
    && artifact.availability === "available"
    && artifact.sha256 === run.atifDigest);
  return atif ? requestedRunId : null;
}

export async function GET(request: Request, context: { params: Promise<{ taskId: string }> }) {
  try {
    const { taskId: rawTaskId } = await context.params;
    const taskId = parseTaskId(rawTaskId);
    const requestedRunId = parseRunId(new URL(request.url).searchParams.get("run"));
    const repository = getCloudRepository();
    const detail = await repository.getTaskDetail(taskId);
    const runId = resolveRunId(detail, requestedRunId);
    if (!detail || !runId) {
      return problemResponse({ code: "NOT_FOUND", status: 404, message: "The selected transcript is not available.", retryable: false });
    }

    const document = await loadVerifiedAtif({
      taskId,
      runId,
      options: {
        repository: { getTaskDetail: async () => detail },
      },
    });
    const data = buildAtifViewModel(document, {
      artifacts: detail.artifacts.filter((artifact) => artifact.runId === runId),
      taskId,
      runId,
    });
    return response(serializeCloudCompleteTrajectory({ schemaVersion: "4.0", generatedAt: new Date().toISOString(), data }), 200);
  } catch (error) {
    return problemResponse(mapError(error));
  }
}

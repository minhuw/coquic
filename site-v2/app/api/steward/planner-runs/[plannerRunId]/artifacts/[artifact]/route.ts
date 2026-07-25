import { NextResponse } from "next/server";
import { Readable } from "node:stream";
import { getArchiveRepository } from "@/lib/steward-archive/repository";

export const dynamic = "force-dynamic";
export const revalidate = 0;

export async function GET(_request: Request, context: { params: Promise<{ plannerRunId: string; artifact: string }> }) {
  const { plannerRunId, artifact } = await context.params;
  try {
    const resource = await getArchiveRepository().readPlannerArtifact(plannerRunId, artifact);
    const encodedFilename = encodeURIComponent(resource.filename);
    return new Response(Readable.toWeb(resource.stream) as ReadableStream, { headers: { "Content-Type": resource.contentType, "Content-Disposition": `attachment; filename="${resource.filename}"; filename*=UTF-8''${encodedFilename}`, "Content-Length": String(resource.size), "X-Content-Type-Options": "nosniff", "Cache-Control": "no-store" } });
  } catch {
    return NextResponse.json({ type: "about:blank", title: "Planner artifact unavailable", status: 404, detail: "The selected planner artifact is not available." }, { status: 404, headers: { "Cache-Control": "no-store" } });
  }
}

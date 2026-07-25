import { NextResponse } from "next/server";
import { getArchiveRepository } from "@/lib/steward-archive/repository";

export const dynamic = "force-dynamic";
export const revalidate = 0;

export async function GET(request: Request, context: { params: Promise<{ plannerRunId: string }> }) {
  const { plannerRunId } = await context.params;
  const query = new URL(request.url).searchParams;
  try {
    const data = await getArchiveRepository().readPlannerTranscript(plannerRunId, query.get("cursor"), Number(query.get("limit") ?? "50"), query.get("artifact") ?? "codex.jsonl");
    if (!data) return NextResponse.json({ type: "about:blank", title: "Planner run not found", status: 404, detail: "The selected planner run is not indexed." }, { status: 404, headers: { "Cache-Control": "no-store" } });
    return NextResponse.json({ schemaVersion: "2.0", generatedAt: new Date().toISOString(), data }, { headers: { "Cache-Control": "no-store" } });
  } catch (error) {
    const code = (error as { code?: string }).code;
    const status = code === "STALE_CURSOR" ? 409 : code === "INVALID_CURSOR" ? 400 : 404;
    return NextResponse.json({ type: "about:blank", title: status === 409 ? "Stale cursor" : "Planner transcript unavailable", status, detail: status === 409 ? "The selected transcript changed; restart loading from the beginning." : "The selected planner transcript is not available." }, { status, headers: { "Cache-Control": "no-store" } });
  }
}

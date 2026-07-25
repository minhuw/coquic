import { NextResponse } from "next/server";
import { getArchiveRepository } from "@/lib/steward-archive/repository";

export const dynamic = "force-dynamic";
export const revalidate = 0;

export async function GET(_request: Request, context: { params: Promise<{ plannerRunId: string }> }) {
  const { plannerRunId } = await context.params;
  try {
    const data = getArchiveRepository().getPlannerRunDetail(plannerRunId);
    if (!data) return NextResponse.json({ type: "about:blank", title: "Planner run not found", status: 404, detail: "The requested planner run is not indexed." }, { status: 404, headers: { "Cache-Control": "no-store" } });
    return NextResponse.json({ schemaVersion: "2.0", generatedAt: new Date().toISOString(), data }, { headers: { "Cache-Control": "no-store" } });
  } catch {
    return NextResponse.json({ type: "about:blank", title: "Planner run unavailable", status: 503, detail: "The selected planner run is temporarily unavailable." }, { status: 503, headers: { "Cache-Control": "no-store" } });
  }
}

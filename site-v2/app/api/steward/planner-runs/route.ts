import { NextResponse } from "next/server";
import { getArchiveRepository } from "@/lib/steward-archive/repository";

export const dynamic = "force-dynamic";
export const revalidate = 0;

export async function GET(request: Request) {
  try {
    const query = new URL(request.url).searchParams;
    const page = getArchiveRepository().listPlannerRunsPage(query.get("cursor"), 50);
    return NextResponse.json({ schemaVersion: "2.0", generatedAt: new Date().toISOString(), data: page }, { headers: { "Cache-Control": "no-store" } });
  } catch (error) {
    const code = (error as { code?: string }).code;
    const status = code === "STALE_CURSOR" ? 409 : code === "INVALID_CURSOR" ? 400 : 503;
    return NextResponse.json({ type: "about:blank", title: status === 409 ? "Stale cursor" : "Planning unavailable", status, detail: status === 409 ? "The planner archive changed; request the first page again." : "The planner archive is not currently available." }, { status, headers: { "Cache-Control": "no-store" } });
  }
}

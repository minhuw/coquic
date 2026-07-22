import { NextResponse } from "next/server";
import { getArchiveRepository } from "@/lib/steward-archive/repository";

export const dynamic = "force-dynamic";
export const revalidate = 0;

export async function GET(request: Request, context: { params: Promise<{ taskId: string }> }) {
  const { taskId } = await context.params;
  const query = new URL(request.url).searchParams;
  try {
    const data = await getArchiveRepository().readTranscriptChunk(taskId, query.get("run") ?? "", query.get("path") ?? "", query.get("cursor"), Number(query.get("limit") ?? "50"));
    return NextResponse.json(data, { headers: { "Cache-Control": "no-store" } });
  } catch (error) {
    const code = (error as { code?: string }).code;
    const status = code === "STALE_CURSOR" ? 409 : code === "INVALID_CURSOR" ? 400 : 404;
    return NextResponse.json({ type: "about:blank", title: status === 409 ? "Stale cursor" : "Transcript unavailable", status, detail: status === 409 ? "The transcript changed; restart loading from the beginning." : "The selected transcript is not available." }, { status, headers: { "Cache-Control": "no-store" } });
  }
}

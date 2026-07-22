import { NextResponse } from "next/server";
import { getArchiveRepository } from "@/lib/steward-archive/repository";

export const dynamic = "force-dynamic";
export const revalidate = 0;

export async function GET(_request: Request, context: { params: Promise<{ taskId: string }> }) {
  const { taskId } = await context.params;
  try {
    const data = await getArchiveRepository().loadTaskDetail(taskId);
    if (!data) return NextResponse.json({ type: "about:blank", title: "Task not found", status: 404, detail: "The requested task is not indexed." }, { status: 404, headers: { "Cache-Control": "no-store" } });
    return NextResponse.json(data, { headers: { "Cache-Control": "no-store" } });
  } catch { return NextResponse.json({ type: "about:blank", title: "Task unavailable", status: 503, detail: "The selected task evidence is temporarily unavailable." }, { status: 503, headers: { "Cache-Control": "no-store" } }); }
}

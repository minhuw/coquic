import { NextResponse } from "next/server";
import { getArchiveRepository } from "@/lib/steward-archive/repository";

export const dynamic = "force-dynamic";
export const revalidate = 0;

export async function GET(request: Request, context: { params: Promise<{ signalId: string }> }) {
  const { signalId } = await context.params;
  const query = new URL(request.url).searchParams;
  try {
    const data = await getArchiveRepository().readSignalEvents(signalId, query.get("cursor"), Number(query.get("limit") ?? "50"));
    if (!data) return NextResponse.json({ type: "about:blank", title: "Signal not found", status: 404, detail: "The selected signal is not indexed." }, { status: 404, headers: { "Cache-Control": "no-store" } });
    return NextResponse.json({ schemaVersion: "2.0", generatedAt: new Date().toISOString(), data }, { headers: { "Cache-Control": "no-store" } });
  } catch (error) {
    const code = (error as { code?: string }).code;
    const status = code === "STALE_CURSOR" ? 409 : code === "INVALID_CURSOR" ? 400 : 404;
    return NextResponse.json({ type: "about:blank", title: status === 409 ? "Stale cursor" : "Signal evidence unavailable", status, detail: status === 409 ? "The selected evidence changed; restart loading from the beginning." : "The selected signal evidence is not available." }, { status, headers: { "Cache-Control": "no-store" } });
  }
}

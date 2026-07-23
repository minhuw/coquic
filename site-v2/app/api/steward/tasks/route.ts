import { NextResponse } from "next/server";
import { getArchiveRepository } from "@/lib/steward-archive/repository";

export const dynamic = "force-dynamic";
export const revalidate = 0;

export async function GET(request: Request) {
  try {
    const query = new URL(request.url).searchParams;
    const repository = getArchiveRepository();
    const page = query.get("scope") === "active" ? repository.listActiveTasksPage(query.get("cursor"), 50) : repository.listTasksPage(query.get("cursor"), 50);
    return NextResponse.json({ schemaVersion: "2.0", generatedAt: new Date().toISOString(), data: page }, { headers: { "Cache-Control": "no-store" } });
  } catch (error) {
    const status = (error as { code?: string }).code === "STALE_CURSOR" ? 409 : 400;
    return NextResponse.json({ type: "about:blank", title: status === 409 ? "Stale cursor" : "Invalid cursor", status, detail: status === 409 ? "The archive changed; request the first page again." : "The page cursor is invalid." }, { status, headers: { "Cache-Control": "no-store" } });
  }
}

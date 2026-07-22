import { NextResponse } from "next/server";
import { getArchiveRepository } from "@/lib/steward-archive/repository";

export const dynamic = "force-dynamic";
export const revalidate = 0;

export async function GET() {
  try { const revision = getArchiveRepository().getRevision(); return NextResponse.json({ schemaVersion: "2.0", generatedAt: new Date().toISOString(), data: revision }, { headers: { "Cache-Control": "no-store" } }); }
  catch { return NextResponse.json({ type: "about:blank", title: "Steward archive unavailable", status: 503, detail: "The archive revision is unavailable." }, { status: 503, headers: { "Cache-Control": "no-store" } }); }
}

import { NextResponse } from "next/server";
import { getArchiveRepository } from "@/lib/steward-archive/repository";

export const dynamic = "force-dynamic";
export const revalidate = 0;

function publicError() {
  return NextResponse.json({ type: "about:blank", title: "Steward archive unavailable", status: 503, detail: "The archive importer is not available." }, { status: 503, headers: { "Cache-Control": "no-store" } });
}

export async function GET() {
  try {
    const status = getArchiveRepository().getImportStatus();
    return NextResponse.json({ schemaVersion: "2.0", generatedAt: new Date().toISOString(), data: { state: status.state, schemaVersion: status.schemaVersion, epochId: status.epochId, revision: status.revision, taskCount: status.taskCount, verifiedTaskCount: status.verifiedTaskCount, errorCount: status.errorCount, lastAttemptAt: status.lastAttemptAt, lastSuccessfulImportAt: status.lastSuccessAt, lagSeconds: status.lagSeconds, watchState: status.watchState } }, { headers: { "Cache-Control": "no-store" } });
  } catch { return publicError(); }
}

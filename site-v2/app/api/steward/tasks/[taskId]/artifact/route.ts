import { NextResponse } from "next/server";
import { getArchiveRepository } from "@/lib/steward-archive/repository";

export const dynamic = "force-dynamic";
export const revalidate = 0;

export async function GET(request: Request, context: { params: Promise<{ taskId: string }> }) {
  const { taskId } = await context.params;
  const path = new URL(request.url).searchParams.get("path");
  try {
    if (!path) throw new Error("missing artifact path");
    const artifact = await getArchiveRepository().readArtifact(taskId, path);
    const filename = encodeURIComponent(artifact.filename).replaceAll("%20", "_");
    return new NextResponse(artifact.bytes, { headers: { "Content-Type": artifact.contentType, "Content-Disposition": `attachment; filename*=UTF-8''${filename}`, "Content-Length": String(artifact.size), "X-Content-Type-Options": "nosniff", "Cache-Control": "no-store" } });
  } catch { return NextResponse.json({ type: "about:blank", title: "Artifact unavailable", status: 404, detail: "The selected artifact is not available." }, { status: 404, headers: { "Cache-Control": "no-store" } }); }
}

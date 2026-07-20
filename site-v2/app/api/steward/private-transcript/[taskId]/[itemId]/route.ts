import { NextResponse } from "next/server";
import { getPrivateTranscriptOutput } from "@/app/steward/tasks/[taskId]/private-transcript";

export async function GET(request: Request, context: { params: Promise<{ taskId: string; itemId: string }> }) {
  const { taskId, itemId } = await context.params;
  const query = new URL(request.url).searchParams;
  const scope = query.get("scope") === "plan" ? "plan" : "attempt";
  const requestedIndex = Number(query.get("index") ?? "0");
  const index = Number.isSafeInteger(requestedIndex) && requestedIndex >= 0 ? requestedIndex : 0;
  const runName = query.get("run") ?? undefined;
  const output = getPrivateTranscriptOutput(taskId, index, itemId, scope, runName);
  if (output === null) return new NextResponse(null, { status: 404 });
  return NextResponse.json(
    { output },
    { headers: { "Cache-Control": "private, no-store" } },
  );
}

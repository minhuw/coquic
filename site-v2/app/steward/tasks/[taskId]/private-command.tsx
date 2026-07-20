"use client";

import { Check, LoaderCircle, Terminal, X } from "lucide-react";
import { useState } from "react";

function formatBytes(value: number) {
  return new Intl.NumberFormat("en-US", { notation: value >= 100_000 ? "compact" : "standard", maximumFractionDigits: 1 }).format(value);
}

export function PrivateCommand({ taskId, itemId, command, exitCode, outputBytes, scope = "attempt", index = 0, transcriptName }: { taskId: string; itemId: string; command: string; exitCode: number | null; outputBytes: number; scope?: "attempt" | "plan"; index?: number; transcriptName?: string }) {
  const [output, setOutput] = useState<string | null>(null);
  const [state, setState] = useState<"idle" | "loading" | "failed">("idle");
  const failed = exitCode !== null && exitCode !== 0;

  async function loadOutput(open: boolean) {
    if (!open || output !== null || state === "loading") return;
    setState("loading");
    try {
      const params = new URLSearchParams();
      if (scope === "plan") params.set("scope", "plan");
      if (index) params.set("index", String(index));
      if (transcriptName) params.set("run", transcriptName);
      const query = params.size ? `?${params}` : "";
      const response = await fetch(`/api/steward/private-transcript/${encodeURIComponent(taskId)}/${encodeURIComponent(itemId)}${query}`, { cache: "no-store" });
      if (!response.ok) throw new Error(`request failed: ${response.status}`);
      const payload = await response.json() as { output: string };
      setOutput(payload.output);
      setState("idle");
    } catch {
      setState("failed");
    }
  }

  return (
    <details data-private-transcript-command onToggle={(event) => void loadOutput(event.currentTarget.open)} className="group border-y border-line">
      <summary className="grid cursor-pointer list-none gap-3 py-3 sm:grid-cols-[minmax(0,1fr)_auto] sm:items-start">
        <span className="flex min-w-0 items-start gap-2 text-xs leading-5 text-ink data-text"><Terminal aria-hidden="true" size={14} className="mt-0.5 shrink-0 text-accent" /><code className="break-all">{command}</code></span>
        <span className={`flex items-center gap-1.5 text-xs font-medium data-text ${failed ? "text-negative" : "text-positive"}`}>
          {failed ? <X aria-hidden="true" size={13} /> : <Check aria-hidden="true" size={13} />}
          {exitCode === null ? "Completed" : `Exit ${exitCode}`} · {formatBytes(outputBytes)} B
        </span>
      </summary>
      <div className="border-t border-line">
        {state === "loading" ? <p className="flex items-center gap-2 px-4 py-5 text-xs text-muted"><LoaderCircle aria-hidden="true" size={14} className="animate-spin" />Loading original output…</p> : null}
        {state === "failed" ? <p className="px-4 py-5 text-xs text-negative">Original command output could not be loaded.</p> : null}
        {output !== null ? <pre className="max-h-[32rem] overflow-auto bg-diff-gutter px-4 py-3 text-xs leading-5 text-ink data-text">{output || "No output"}</pre> : null}
      </div>
    </details>
  );
}

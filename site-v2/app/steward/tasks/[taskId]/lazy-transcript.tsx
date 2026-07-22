"use client";

import { useRef, useState } from "react";

export interface TranscriptRecord {
  ordinal: number;
  timestamp: string | null;
  value: unknown;
  id?: string;
  kind?: string;
  label?: string;
  text?: string;
  command?: string;
  output?: string;
  exitCode?: number | null;
}

interface Props { taskId: string; runId?: string; path?: string | null; initial: TranscriptRecord[]; initialCount: number }

function recordLabel(record: TranscriptRecord) {
  if (record.label) return record.label;
  if (record.command) return record.command;
  if (record.text) return record.text;
  return typeof record.value === "string" ? record.value : "Archive record";
}

export function LazyTranscript({ taskId, runId, path, initial, initialCount }: Props) {
  const [records, setRecords] = useState<TranscriptRecord[]>(initial);
  const [cursor, setCursor] = useState<string | null>(null);
  const [hasMore, setHasMore] = useState(Boolean(runId && path));
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const loaded = useRef(false);
  async function loadMore() {
    if (!runId || !path || loading || !hasMore) return;
    setLoading(true); setError(null);
    try {
      const query = new URLSearchParams({ run: runId, path });
      if (cursor) query.set("cursor", cursor);
      const response = await fetch(`/api/steward/tasks/${encodeURIComponent(taskId)}/transcript?${query}`, { cache: "no-store" });
      if (!response.ok) throw new Error(response.status === 409 ? "Transcript changed; retry from the beginning." : "Transcript chunk unavailable.");
      const payload = await response.json() as { data: { records: TranscriptRecord[]; nextCursor: string | null; hasMore: boolean } };
      setRecords((current) => { const seen = new Set(current.map((record) => record.ordinal)); return [...current, ...payload.data.records.filter((record) => record.ordinal >= initialCount && !seen.has(record.ordinal))]; });
      setCursor(payload.data.nextCursor);
      setHasMore(payload.data.hasMore);
      loaded.current = true;
    } catch (cause) { setError(cause instanceof Error ? cause.message : "Transcript chunk unavailable."); }
    finally { setLoading(false); }
  }
  return <div>
    <ol className="min-w-0 border-t border-line">{records.map((record, index) => <li id={`archive-event-${record.ordinal}`} key={`archive-${record.ordinal}`} className="scroll-mt-24 border-b border-line py-6"><article><header className="flex flex-col gap-1 sm:flex-row sm:items-baseline sm:justify-between sm:gap-6"><div className="flex min-w-0 items-baseline gap-3"><p className="shrink-0 text-xs font-medium text-muted data-text">{String(index + 1).padStart(2, "0")} / {record.kind ?? "Archive"}</p><h3 className="min-w-0 text-sm font-semibold text-ink [overflow-wrap:anywhere]">{recordLabel(record)}</h3></div>{record.timestamp ? <time className="shrink-0 text-xs text-faint data-text" dateTime={record.timestamp}>{new Intl.DateTimeFormat("en-US", { month: "short", day: "numeric", hour: "numeric", minute: "2-digit", timeZone: "UTC", timeZoneName: "short" }).format(new Date(record.timestamp))}</time> : null}</header>{record.command ? <pre className="mt-3 max-h-72 overflow-auto border-y border-line bg-diff-gutter px-4 py-3 text-xs leading-5 text-ink data-text">{record.command}</pre> : <p className="mt-3 text-sm leading-7 text-muted">{record.text ?? (typeof record.value === "string" ? record.value : JSON.stringify(record.value))}</p>}</article></li>)}</ol>
    {runId && path ? <div className="mt-5 flex flex-wrap items-center gap-4"><button type="button" className="border border-line-strong px-3 py-2 text-xs font-medium text-ink" onClick={() => void loadMore()} disabled={loading || !hasMore}>{loading ? "Loading" : hasMore ? "Load more" : "All complete records loaded"}</button><span aria-live="polite" className="text-xs text-muted">{error ?? (loaded.current && !hasMore ? "Transcript complete." : "")}</span></div> : null}
  </div>;
}

"use client";

import { useEffect, useRef, useState } from "react";

type EvidenceRecord = { eventId?: string; sequence?: number; occurredAt?: string; kind?: string; ordinal?: number; value?: Record<string, unknown>; payload?: Record<string, unknown> };
type EvidencePage = { records: EvidenceRecord[]; nextCursor: string | null; resumeCursor: string };

export function mergeEvidenceRecords(current: EvidenceRecord[], incoming: EvidenceRecord[], key: (record: EvidenceRecord) => string) {
  const seen = new Set(current.map(key));
  return [...current, ...incoming.filter((record) => !seen.has(key(record)) && seen.add(key(record)))];
}

export async function loadEvidenceFrontier(request: (cursor: string | null) => Promise<EvidencePage>, cursor: string | null, key: (record: EvidenceRecord) => string) {
  let page = await request(cursor);
  let records = page.records;
  while (page.nextCursor) {
    page = await request(page.nextCursor);
    records = mergeEvidenceRecords(records, page.records, key);
  }
  return { ...page, records };
}

export async function refreshEvidenceFrontier(request: (cursor: string | null) => Promise<EvidencePage>, cursor: string | null, key: (record: EvidenceRecord) => string) {
  try {
    return await loadEvidenceFrontier(request, cursor, key);
  } catch (error) {
    if ((error as { status?: number }).status !== 409) throw error;
    return loadEvidenceFrontier(request, null, key);
  }
}

export function SignalEvidence({ signalId }: { signalId: string }) {
  const [records, setRecords] = useState<EvidenceRecord[]>([]);
  const [cursor, setCursor] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);
  const focusRef = useRef<HTMLButtonElement>(null);
  const recordsRef = useRef<EvidenceRecord[]>([]);
  const resumeRef = useRef<string | null>(null);
  const request = async (next: string | null) => {
    const response = await fetch(`/api/steward/signals/${encodeURIComponent(signalId)}/events${next ? `?cursor=${encodeURIComponent(next)}` : ""}`, { cache: "no-store" });
    if (!response.ok) throw Object.assign(new Error("unavailable"), { status: response.status });
    const body = await response.json() as { data: EvidencePage };
    return body.data;
  };
  const apply = (page: EvidencePage, replace: boolean) => {
    const next = replace ? page.records : mergeEvidenceRecords(recordsRef.current, page.records, (record) => String(record.eventId));
    recordsRef.current = next; setRecords(next); setCursor(page.nextCursor); resumeRef.current = page.resumeCursor;
  };
  const load = async (next: string | null, replace = false) => {
    setLoading(true); setError(false);
    try { apply(await request(next), replace); } catch { setError(true); } finally { setLoading(false); }
  };
  useEffect(() => { recordsRef.current = []; resumeRef.current = null; setRecords([]); void load(null, true); }, [signalId]);
  useEffect(() => {
    const refresh = async () => {
      setLoading(true); setError(false);
      try { apply(await refreshEvidenceFrontier(request, resumeRef.current, (record) => String(record.eventId)), false); }
      catch { setError(true); }
      finally { setLoading(false); }
    };
    const onRevision = () => { void refresh(); };
    window.addEventListener("steward-revision", onRevision);
    return () => window.removeEventListener("steward-revision", onRevision);
  }, [signalId]);
  useEffect(() => { if (!loading) focusRef.current?.focus(); }, [loading, records.length]);
  return <section aria-label="Signal evidence" className="mt-6 border-t border-line pt-5"><div className="flex items-baseline justify-between gap-4"><h3 className="text-sm font-semibold text-ink">Indexed evidence</h3><span className="text-xs text-muted data-text">{records.length} loaded</span></div>{error ? <p className="mt-4 text-sm text-negative">Signal evidence is temporarily unavailable.</p> : <ol className="mt-3 border-t border-line">{records.map((record) => <li key={record.eventId ?? `${record.sequence}-${record.ordinal}`} className="border-b border-line py-3"><div className="flex flex-wrap gap-x-3 gap-y-1 text-xs text-muted"><span className="data-text">{record.sequence ?? record.ordinal}</span><span>{record.kind}</span><span className="data-text">{record.occurredAt}</span></div><pre className="mt-2 max-w-full overflow-x-auto whitespace-pre-wrap break-words text-xs leading-5 text-ink">{JSON.stringify(record.payload ?? record.value ?? {}, null, 2)}</pre></li>)}</ol>}{loading ? <p className="mt-4 text-sm text-muted" role="status">Loading evidence...</p> : cursor ? <button ref={focusRef} type="button" onClick={() => void load(cursor)} className="mt-4 border border-line-strong px-3 py-2 text-xs font-medium text-ink hover:border-accent">Load more signal evidence</button> : <button ref={focusRef} type="button" disabled className="mt-4 text-xs text-muted">All indexed signal evidence loaded</button>}</section>;
}

export function PlannerTranscript({ plannerRunId, artifact = "codex.jsonl" }: { plannerRunId: string; artifact?: string }) {
  const [records, setRecords] = useState<EvidenceRecord[]>([]);
  const [cursor, setCursor] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);
  const focusRef = useRef<HTMLButtonElement>(null);
  const recordsRef = useRef<EvidenceRecord[]>([]);
  const resumeRef = useRef<string | null>(null);
  const request = async (next: string | null) => {
    const params = new URLSearchParams({ artifact }); if (next) params.set("cursor", next);
    const response = await fetch(`/api/steward/planner-runs/${encodeURIComponent(plannerRunId)}/transcript?${params}`, { cache: "no-store" });
    if (!response.ok) throw Object.assign(new Error("unavailable"), { status: response.status });
    const body = await response.json() as { data: EvidencePage };
    return body.data;
  };
  const apply = (page: EvidencePage, replace: boolean) => {
    const next = replace ? page.records : mergeEvidenceRecords(recordsRef.current, page.records, (record) => String(record.ordinal));
    recordsRef.current = next; setRecords(next); setCursor(page.nextCursor); resumeRef.current = page.resumeCursor;
  };
  const load = async (next: string | null, replace = false) => {
    setLoading(true); setError(false);
    try { apply(await request(next), replace); } catch { setError(true); } finally { setLoading(false); }
  };
  useEffect(() => { recordsRef.current = []; resumeRef.current = null; setRecords([]); void load(null, true); }, [plannerRunId, artifact]);
  useEffect(() => {
    const refresh = async () => {
      setLoading(true); setError(false);
      try { apply(await loadEvidenceFrontier(request, resumeRef.current, (record) => String(record.ordinal)), recordsRef.current.length === 0); }
      catch { setError(true); }
      finally { setLoading(false); }
    };
    const onRevision = () => { void refresh(); };
    window.addEventListener("steward-revision", onRevision);
    return () => window.removeEventListener("steward-revision", onRevision);
  }, [plannerRunId, artifact]);
  useEffect(() => { if (!loading) focusRef.current?.focus(); }, [loading, records.length]);
  return <section aria-label="Planner transcript" className="mt-6 border-t border-line pt-5"><div className="flex items-baseline justify-between gap-4"><h3 className="text-sm font-semibold text-ink">Planner transcript</h3><span className="text-xs text-muted data-text">{records.length} loaded</span></div>{error ? <p className="mt-4 text-sm text-negative">Planner transcript is unavailable until its manifest is verified.</p> : <ol className="mt-3 border-t border-line">{records.map((record) => <li key={`${record.ordinal}-${JSON.stringify(record.value)}`} className="border-b border-line py-3"><div className="text-xs text-muted data-text">Record {Number(record.ordinal) + 1}</div><pre className="mt-2 max-w-full overflow-x-auto whitespace-pre-wrap break-words text-xs leading-5 text-ink">{JSON.stringify(record.value ?? {}, null, 2)}</pre></li>)}</ol>}{loading ? <p className="mt-4 text-sm text-muted" role="status">Loading transcript...</p> : cursor ? <button ref={focusRef} type="button" onClick={() => void load(cursor)} className="mt-4 border border-line-strong px-3 py-2 text-xs font-medium text-ink hover:border-accent">Load more transcript records</button> : <button ref={focusRef} type="button" disabled className="mt-4 text-xs text-muted">All complete transcript records loaded</button>}</section>;
}

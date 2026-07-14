'use client';

import {
  ArrowLeft,
  CalendarDays,
  ChevronDown,
  Database,
  Download,
  FileJson,
  RotateCcw,
  Search,
  X,
} from 'lucide-react';
import { usePathname, useRouter, useSearchParams } from 'next/navigation';
import { useEffect, useMemo, useRef, useState } from 'react';

import { CodexTranscriptThread, transcriptDisplayCount } from '@/components/codex-transcript-thread';
import { PageHeader } from '@/components/page-header';
import type { TranscriptRecord, TranscriptRole } from '@/lib/codex-transcript';

interface TranscriptSample {
  role: TranscriptRole;
  timestamp: string;
  phase: string;
  text: string;
}

export interface TranscriptSession {
  id: string;
  filename: string;
  archiveMember: string;
  bytes: number;
  compressedBytes: number;
  modifiedAt: string;
  startedAt: string;
  sessionId: string;
  cwd: string;
  originator: string;
  source: string;
  cliVersion: string;
  modelProvider: string;
  model: string;
  lines: number;
  messageCount: number;
  userMessages: number;
  assistantMessages: number;
  developerMessages: number;
  eventCount: number;
  toolCalls: number;
  compactedCount: number;
  title: string;
  preview: string;
  samples: TranscriptSample[];
}

export interface TranscriptManifest {
  generatedAt: string;
  archive: string;
  archiveUrl: string;
  archiveBytes: number;
  transcriptCount: number;
  totalBytes: number;
  totalLines: number;
  totalMessages: number;
  totalUserMessages: number;
  totalAssistantMessages: number;
  totalToolCalls: number;
  totalTokens: number;
  dateRange?: { start: string; end: string };
  sources?: { name: string; href: string; note: string }[];
}

export interface TranscriptSearchResponse {
  manifest: TranscriptManifest;
  query: string;
  from: string;
  to: string;
  page: number;
  pageSize: number;
  total: number;
  totalPages: number;
  sessions: TranscriptSession[];
}

export interface TranscriptSessionDetail {
  sessionId: string;
  archiveMember: string;
  bytes: number;
  totalLines: number;
  records: TranscriptRecord[];
  hasMore: boolean;
  nextCursor: number;
  scannedLines: number;
  scanLimited: boolean;
  limit: number;
}

type CollectionData = TranscriptSearchResponse & { updatedAt: number };
type CollectionState =
  | { status: 'idle' }
  | { status: 'loading'; previous?: CollectionData }
  | { status: 'ready-empty'; data: CollectionData }
  | { status: 'ready-populated'; data: CollectionData }
  | { status: 'unavailable'; message: string; previous?: CollectionData }
  | { status: 'error'; message: string; previous?: CollectionData };

type DetailData = TranscriptSessionDetail & { updatedAt: number };
type DetailState =
  | { status: 'idle' }
  | { status: 'loading'; session: string; previous?: DetailData }
  | { status: 'ready-empty'; session: string; data: DetailData }
  | { status: 'ready-populated'; session: string; data: DetailData }
  | { status: 'not-found'; session: string }
  | { status: 'unavailable'; session: string; message: string; previous?: DetailData }
  | { status: 'error'; session: string; message: string; previous?: DetailData };

type LoadMoreState =
  | { status: 'idle' }
  | { status: 'loading' }
  | { status: 'error'; message: string }
  | { status: 'exhausted' };

type OwnedParams = { q: string; from: string; to: string; page: number; session: string };

const datePresets = [7, 30, 90] as const;
export const transcriptPageSize = 25;
export const transcriptChunkSize = 80;
export const searchDebounceMs = 250;
export const listScrollStorageKey = 'coquic-transcript:list-scroll:v1';
const ownedParamNames = ['q', 'from', 'to', 'page', 'session'] as const;

export function readOwnedParams(searchParams: Pick<URLSearchParams, 'get'>): OwnedParams {
  const from = normalizeDate(searchParams.get('from'));
  const to = normalizeDate(searchParams.get('to'));
  const datesAreReversed = Boolean(from && to && from > to);
  return {
    q: searchParams.get('q')?.trim() ?? '',
    from: datesAreReversed ? to : from,
    to: datesAreReversed ? from : to,
    page: normalizePage(searchParams.get('page')),
    session: normalizeSession(searchParams.get('session')),
  };
}

export function collectionScrollKey(params: Pick<OwnedParams, 'q' | 'from' | 'to' | 'page'>) {
  const key = new URLSearchParams();
  if (params.from) key.set('from', params.from);
  if (params.page > 1) key.set('page', String(params.page));
  if (params.q) key.set('q', params.q);
  if (params.to) key.set('to', params.to);
  key.sort();
  return key.toString();
}

export function TranscriptDataset() {
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();
  const searchString = searchParams.toString();
  const owned = useMemo(() => readOwnedParams(new URLSearchParams(searchString)), [searchString]);
  const [queryDraft, setQueryDraft] = useState(owned.q);
  const [datePickerOpen, setDatePickerOpen] = useState(false);
  const [pageDraft, setPageDraft] = useState(String(owned.page));
  const [collection, setCollection] = useState<CollectionState>({ status: 'idle' });
  const [detail, setDetail] = useState<DetailState>({ status: 'idle' });
  const [loadMore, setLoadMore] = useState<LoadMoreState>({ status: 'idle' });
  const [datasetDateRange, setDatasetDateRange] = useState<TranscriptManifest['dateRange'] | null>(null);
  const [collectionRetry, setCollectionRetry] = useState(0);
  const [detailRetry, setDetailRetry] = useState(0);
  const collectionRequestRef = useRef(0);
  const detailRequestRef = useRef(0);
  const loadMoreControllerRef = useRef<AbortController | null>(null);
  const datePickerRef = useRef<HTMLDivElement>(null);
  const dateTriggerRef = useRef<HTMLButtonElement>(null);
  const dateFromInputRef = useRef<HTMLInputElement>(null);
  const dateToInputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLElement>(null);

  const collectionData = currentCollection(collection);
  const sessions = collectionData?.sessions ?? [];
  const selectedSession = sessions.find((session) => session.id === owned.session) ?? null;
  const selectedDetail: DetailState = detailSession(detail) === owned.session
    ? detail
    : { status: 'loading', session: owned.session };
  const detailData = currentDetail(selectedDetail);
  const records = detailData?.records ?? [];
  const conversationItemCount = transcriptDisplayCount(records);
  const total = collectionData?.total ?? 0;
  const totalPages = collectionData?.totalPages ?? 1;
  const visibleStart = total === 0 ? 0 : (owned.page - 1) * transcriptPageSize + 1;
  const visibleEnd = Math.min(total, (owned.page - 1) * transcriptPageSize + sessions.length);
  const datePresetBase = datasetDateRange ?? collectionData?.manifest.dateRange ?? null;
  const datasetDateMin = normalizeDate(datasetDateRange?.start.slice(0, 10));
  const datasetDateMax = normalizeDate(datasetDateRange?.end.slice(0, 10));
  const collectionKey = collectionScrollKey(owned);

  function navigate(mode: 'push' | 'replace', update: (params: URLSearchParams) => void) {
    const next = new URLSearchParams(searchString);
    update(next);
    canonicalizeOwnedParams(next);
    const query = next.toString();
    router[mode](query ? `${pathname}?${query}` : pathname, { scroll: false });
  }

  function replaceFilters(nextFilters: Partial<Pick<OwnedParams, 'q' | 'from' | 'to'>>) {
    navigate('replace', (next) => {
      if ('q' in nextFilters) setOrDelete(next, 'q', nextFilters.q?.trim() ?? '');
      if ('from' in nextFilters) setOrDelete(next, 'from', normalizeDate(nextFilters.from ?? ''));
      if ('to' in nextFilters) setOrDelete(next, 'to', normalizeDate(nextFilters.to ?? ''));
      next.delete('page');
      next.delete('session');
    });
  }

  function rememberListScroll() {
    writeListScroll(collectionKey, listRef.current?.scrollTop ?? 0);
  }

  useEffect(() => {
    setQueryDraft(owned.q);
    setPageDraft(String(owned.page));
  }, [owned.page, owned.q]);

  useEffect(() => {
    const next = new URLSearchParams(searchString);
    const before = next.toString();
    canonicalizeOwnedParams(next);
    if (next.toString() === before) return;
    const query = next.toString();
    router.replace(query ? `${pathname}?${query}` : pathname, { scroll: false });
  }, [pathname, router, searchString]);

  useEffect(() => {
    const normalized = queryDraft.trim();
    if (normalized === owned.q) return;
    const timeout = window.setTimeout(() => replaceFilters({ q: normalized }), searchDebounceMs);
    return () => window.clearTimeout(timeout);
  }, [queryDraft, owned.q, searchString]);

  useEffect(() => {
    const requestId = ++collectionRequestRef.current;
    const controller = new AbortController();
    const params = new URLSearchParams({ page: String(owned.page) });
    if (owned.q) params.set('q', owned.q);
    if (owned.from) params.set('from', owned.from);
    if (owned.to) params.set('to', owned.to);
    setCollection((current) => ({ status: 'loading', previous: currentCollection(current) }));

    void fetch(`/transcript/api/search?${params.toString()}`, { signal: controller.signal })
      .then(async (response) => {
        if (!response.ok) throw new RequestError(response.status, `Transcript search returned ${response.status}`);
        return (await response.json()) as TranscriptSearchResponse;
      })
      .then((result) => {
        if (requestId !== collectionRequestRef.current) return;
        const data = { ...result, updatedAt: Date.now() };
        if (!owned.q && !owned.from && !owned.to && result.manifest.dateRange) {
          setDatasetDateRange(result.manifest.dateRange);
        }
        setCollection(result.sessions.length === 0 ? { status: 'ready-empty', data } : { status: 'ready-populated', data });
        if (result.page !== owned.page) {
          navigate('replace', (next) => setCanonicalPage(next, result.page));
        }
      })
      .catch((error: unknown) => {
        if (controller.signal.aborted || requestId !== collectionRequestRef.current) return;
        setCollection((current) => {
          const previous = currentCollection(current);
          if (error instanceof RequestError && error.status === 503) {
            return { status: 'unavailable', message: 'The transcript index is currently unavailable.', previous };
          }
          return { status: 'error', message: 'The transcript list could not be refreshed.', previous };
        });
      });
    return () => controller.abort();
  }, [collectionRetry, owned.from, owned.page, owned.q, owned.to]);

  useEffect(() => {
    loadMoreControllerRef.current?.abort();
    setLoadMore({ status: 'idle' });
    if (!owned.session) {
      setDetail({ status: 'idle' });
      return;
    }

    const requestId = ++detailRequestRef.current;
    const controller = new AbortController();
    setDetail((current) => ({
      status: 'loading',
      session: owned.session,
      previous: detailSession(current) === owned.session ? currentDetail(current) : undefined,
    }));
    const params = new URLSearchParams({ limit: String(transcriptChunkSize) });
    void fetch(`/transcript/api/session/${encodeURIComponent(owned.session)}?${params.toString()}`, { signal: controller.signal })
      .then(async (response) => {
        if (!response.ok) throw new RequestError(response.status, `Transcript session returned ${response.status}`);
        return (await response.json()) as TranscriptSessionDetail;
      })
      .then((result) => {
        if (requestId !== detailRequestRef.current) return;
        const data = { ...result, updatedAt: Date.now() };
        setDetail(result.records.length === 0 ? { status: 'ready-empty', session: owned.session, data } : { status: 'ready-populated', session: owned.session, data });
        setLoadMore(result.hasMore ? { status: 'idle' } : { status: 'exhausted' });
      })
      .catch((error: unknown) => {
        if (controller.signal.aborted || requestId !== detailRequestRef.current) return;
        if (error instanceof RequestError && error.status === 404) {
          setDetail({ status: 'not-found', session: owned.session });
          return;
        }
        setDetail((current) => {
          const previous = currentDetail(current);
          if (error instanceof RequestError && error.status === 503) {
            return { status: 'unavailable', session: owned.session, message: 'The transcript source is currently unavailable.', previous };
          }
          return { status: 'error', session: owned.session, message: 'This transcript could not be loaded.', previous };
        });
      });
    return () => controller.abort();
  }, [detailRetry, owned.session]);

  useEffect(() => {
    if (!isCollectionReady(collection)) return;
    const frame = window.requestAnimationFrame(() => {
      if (listRef.current) listRef.current.scrollTop = readListScroll(collectionKey);
    });
    return () => window.cancelAnimationFrame(frame);
  }, [collection.status, collectionKey, owned.session]);

  useEffect(() => {
    if (!datePickerOpen) return;
    function close(returnFocus: boolean) {
      setDatePickerOpen(false);
      if (returnFocus) window.requestAnimationFrame(() => dateTriggerRef.current?.focus());
    }
    function handlePointerDown(event: PointerEvent) {
      if (!datePickerRef.current?.contains(event.target as Node)) close(true);
    }
    function handleKeyDown(event: KeyboardEvent) {
      if (event.key === 'Escape') close(true);
    }
    document.addEventListener('pointerdown', handlePointerDown);
    document.addEventListener('keydown', handleKeyDown);
    return () => {
      document.removeEventListener('pointerdown', handlePointerDown);
      document.removeEventListener('keydown', handleKeyDown);
    };
  }, [datePickerOpen]);

  function changePage(nextPage: number) {
    rememberListScroll();
    navigate('push', (next) => {
      setCanonicalPage(next, Math.min(totalPages, Math.max(1, nextPage)));
      next.delete('session');
    });
  }

  function selectSession(session: TranscriptSession) {
    navigate('push', (next) => next.set('session', session.id));
  }

  function backToResults() {
    navigate('replace', (next) => next.delete('session'));
  }

  function clearFilters() {
    setQueryDraft('');
    navigate('replace', (next) => ownedParamNames.forEach((name) => next.delete(name)));
  }

  function commitPageDraft() {
    const parsed = Number(pageDraft);
    if (!Number.isFinite(parsed)) {
      setPageDraft(String(owned.page));
      return;
    }
    const nextPage = Math.min(totalPages, Math.max(1, Math.trunc(parsed)));
    setPageDraft(String(nextPage));
    if (nextPage !== owned.page) changePage(nextPage);
  }

  function applyDatePreset(days: (typeof datePresets)[number]) {
    const end = dateRangeEndDate(datePresetBase) ?? new Date();
    const start = new Date(end);
    start.setUTCDate(start.getUTCDate() - days + 1);
    replaceFilters({ from: toDateInputValue(start), to: toDateInputValue(end) });
    setDatePickerOpen(false);
    dateTriggerRef.current?.focus();
  }

  function loadMoreTranscript() {
    if (!owned.session || !detailData || loadMore.status === 'loading' || !detailData.hasMore) return;
    const controller = new AbortController();
    loadMoreControllerRef.current?.abort();
    loadMoreControllerRef.current = controller;
    const session = owned.session;
    const params = new URLSearchParams({ cursor: String(detailData.nextCursor), limit: String(transcriptChunkSize) });
    setLoadMore({ status: 'loading' });
    void fetch(`/transcript/api/session/${encodeURIComponent(session)}?${params.toString()}`, { signal: controller.signal })
      .then(async (response) => {
        if (!response.ok) throw new RequestError(response.status, `Transcript session returned ${response.status}`);
        return (await response.json()) as TranscriptSessionDetail;
      })
      .then((result) => {
        if (owned.session !== session) return;
        setDetail((current) => {
          const currentData = currentDetail(current);
          if (!currentData || currentData.sessionId !== result.sessionId) return current;
          const data = { ...result, records: [...currentData.records, ...result.records], updatedAt: Date.now() };
          return data.records.length === 0 ? { status: 'ready-empty', session, data } : { status: 'ready-populated', session, data };
        });
        setLoadMore(result.hasMore ? { status: 'idle' } : { status: 'exhausted' });
      })
      .catch(() => {
        if (!controller.signal.aborted) setLoadMore({ status: 'error', message: 'More records could not be loaded.' });
      });
  }

  const manifest = collectionData?.manifest;
  const collectionBusy = collection.status === 'idle' || collection.status === 'loading';
  const hasFilters = Boolean(owned.q || owned.from || owned.to);

  return (
    <section className="transcript-shell" aria-labelledby="transcript-title" data-mode={owned.session ? 'detail' : 'collection'}>
      <PageHeader
        className="transcript-header"
        eyebrow="Public dataset"
        title="CoQUIC Transcript Dataset"
        description="Development transcripts from the Codex sessions that built CoQUIC, indexed for browsing and available as raw JSONL."
        actions={
          manifest?.archiveBytes && manifest.archiveUrl ? (
            <a className="transcript-primary-action" href={manifest.archiveUrl} download>
              <Download aria-hidden="true" />
              <span>Download dataset</span>
              <small>{formatBytes(manifest.archiveBytes)}</small>
            </a>
          ) : (
            <span className="transcript-primary-action is-disabled" aria-disabled="true">
              <Download aria-hidden="true" />
              <span>Archive unavailable</span>
            </span>
          )
        }
      />

      {manifest ? (
        <dl className="transcript-summary" aria-label="Dataset summary">
          <Summary label="Transcripts" value={formatInteger(manifest.transcriptCount)} />
          <Summary label="Date range" value={formatDateRange(manifest.dateRange)} />
          <Summary label="Total tokens" value={formatInteger(manifest.totalTokens)} />
          <Summary label="Tool calls" value={formatInteger(manifest.totalToolCalls)} />
        </dl>
      ) : (
        <div className="transcript-summary-skeleton" aria-label="Dataset summary loading">Loading dataset summary</div>
      )}

      <div className="transcript-controls" aria-label="Transcript filters">
        <div className="transcript-search-wrap">
          <label className="transcript-search">
            <Search aria-hidden="true" />
            <input value={queryDraft} onChange={(event) => setQueryDraft(event.target.value)} aria-label="Search transcript sessions" placeholder="Search titles, paths, session IDs" type="search" />
            {queryDraft ? (
              <button type="button" aria-label="Clear transcript search" onClick={() => setQueryDraft('')}><X aria-hidden="true" /></button>
            ) : null}
          </label>
          <span className="transcript-search-feedback" role="status">
            {collectionBusy ? 'Searching' : `${formatInteger(total)} result${total === 1 ? '' : 's'}`}
          </span>
        </div>

        <div className="transcript-date-filter" data-open={datePickerOpen ? 'true' : undefined} ref={datePickerRef}>
          <button className="transcript-date-trigger" type="button" aria-expanded={datePickerOpen} aria-haspopup="dialog" ref={dateTriggerRef} onClick={() => setDatePickerOpen((open) => !open)}>
            <CalendarDays aria-hidden="true" />
            <span><small>Date range</small><b>{formatDateFilterLabel(owned.from, owned.to)}</b></span>
            <ChevronDown aria-hidden="true" />
          </button>
          {datePickerOpen ? (
            <div className="transcript-date-panel" role="dialog" aria-label="Transcript date range">
              <div className="transcript-date-presets" role="group" aria-label="Quick date ranges">
                <button type="button" data-active={!owned.from && !owned.to ? 'true' : undefined} onClick={() => { replaceFilters({ from: '', to: '' }); setDatePickerOpen(false); dateTriggerRef.current?.focus(); }}>All</button>
                {datePresets.map((days) => <button key={days} type="button" data-active={isDatePresetActive(days, owned.from, owned.to, datePresetBase) ? 'true' : undefined} onClick={() => applyDatePreset(days)}>{days}D</button>)}
              </div>
              <div className="transcript-date-fields">
                <label><span>From</span><span className="transcript-date-input"><input aria-label="Filter transcripts from date" min={datasetDateMin || undefined} max={owned.to || datasetDateMax || undefined} onChange={(event) => replaceFilters({ from: event.target.value })} ref={dateFromInputRef} type="date" value={owned.from} /><button type="button" aria-label="Open from-date calendar" onClick={() => openNativeDatePicker(dateFromInputRef.current)}><CalendarDays aria-hidden="true" /></button></span></label>
                <label><span>To</span><span className="transcript-date-input"><input aria-label="Filter transcripts to date" min={owned.from || datasetDateMin || undefined} max={datasetDateMax || undefined} onChange={(event) => replaceFilters({ to: event.target.value })} ref={dateToInputRef} type="date" value={owned.to} /><button type="button" aria-label="Open to-date calendar" onClick={() => openNativeDatePicker(dateToInputRef.current)}><CalendarDays aria-hidden="true" /></button></span></label>
              </div>
            </div>
          ) : null}
        </div>
        {hasFilters ? <button className="transcript-clear-filters" type="button" onClick={clearFilters}><RotateCcw aria-hidden="true" />Clear filters</button> : null}
      </div>

      <div className="transcript-workspace">
        <aside className="transcript-list" aria-label="Transcript sessions" ref={listRef} tabIndex={0} onScroll={rememberListScroll}>
          <div className="transcript-list-head"><b>{formatInteger(total)} sessions</b><span>{formatInteger(visibleStart)}-{formatInteger(visibleEnd)}</span></div>
          {collection.status === 'idle' || (collection.status === 'loading' && !collection.previous) ? (
            <RequestState icon={<Database aria-hidden="true" />} title="Loading transcripts" reason="Fetching the current collection." />
          ) : null}
          {collection.status === 'unavailable' || collection.status === 'error' ? (
            <RequestBanner tone="danger" message={`${collection.message}${collection.previous ? ` Showing results updated ${formatUpdatedAt(collection.previous.updatedAt)}.` : ''}`} action="Retry" onAction={() => setCollectionRetry((value) => value + 1)} />
          ) : null}
          {collectionData && sessions.length === 0 ? (
            <RequestState title="No transcripts found" reason={hasFilters ? 'No transcript matches the current filters.' : 'The dataset contains no transcript sessions.'} action={hasFilters ? 'Clear filters' : undefined} onAction={hasFilters ? clearFilters : undefined} />
          ) : null}
          {sessions.map((session) => (
            <button key={session.id} type="button" className="transcript-row" data-active={owned.session === session.id ? 'true' : undefined} aria-current={owned.session === session.id ? 'true' : undefined} onPointerDown={rememberListScroll} onClick={(event) => { if (event.detail === 0) rememberListScroll(); selectSession(session); }}>
              <span className="transcript-row-marker" aria-hidden="true" />
              <span className="transcript-row-top"><b>{session.title}</b><small>{formatBytes(session.bytes)}</small></span>
              <span className="transcript-row-preview">{session.preview}</span>
              <span className="transcript-row-meta">{formatDateTime(session.startedAt)}</span>
            </button>
          ))}
          {collectionData ? (
            <div className="transcript-pagination" aria-label="Transcript pages">
              <button type="button" disabled={owned.page <= 1 || collectionBusy} onClick={() => changePage(owned.page - 1)}>Previous</button>
              <label><span>Page</span><input value={pageDraft} aria-label={`Jump to transcript page, 1 through ${totalPages}`} inputMode="numeric" min={1} max={totalPages} type="number" disabled={collectionBusy || totalPages <= 1} onBlur={commitPageDraft} onChange={(event) => setPageDraft(event.target.value)} onKeyDown={(event) => { if (event.key === 'Enter') event.currentTarget.blur(); }} /><span>of {formatInteger(totalPages)}</span></label>
              <button type="button" disabled={owned.page >= totalPages || collectionBusy} onClick={() => changePage(owned.page + 1)}>Next</button>
            </div>
          ) : null}
        </aside>

        <article className="transcript-viewer" aria-label="Selected transcript preview" tabIndex={0}>
          {!owned.session ? <RequestState title="Select a transcript" reason="Choose a session from the collection to inspect its records and downloads." /> : (
            <>
              <button className="transcript-back" type="button" onClick={backToResults}><ArrowLeft aria-hidden="true" />Back to results</button>
              <header className="transcript-viewer-head">
                <div><span className="transcript-viewer-id">{owned.session}</span><h2>{selectedSession?.title ?? 'Transcript session'}</h2><p>{selectedSession?.preview ?? 'Deep-linked transcript detail.'}</p></div>
                <div className="transcript-download-actions">
                  <a href={`/transcript/api/session/${encodeURIComponent(owned.session)}/raw`} download><FileJson aria-hidden="true" /><span>JSONL</span></a>
                  {manifest?.archiveBytes && manifest.archiveUrl ? <a href={manifest.archiveUrl} download><Download aria-hidden="true" /><span>ZIP</span></a> : <span aria-disabled="true"><Download aria-hidden="true" /><span>ZIP unavailable</span></span>}
                </div>
              </header>

              {selectedSession ? (
                <dl className="transcript-meta-grid">
                  <Meta label="Started" value={formatDateTime(selectedSession.startedAt)} />
                  <Meta label="Session ID" value={selectedSession.sessionId} />
                  <Meta label="Source" value={[selectedSession.originator, selectedSession.source].filter(Boolean).join(' / ')} />
                  <Meta label="CLI" value={selectedSession.cliVersion || 'unknown'} />
                </dl>
              ) : null}

              <div className="transcript-detail-body" aria-live="polite">
                {selectedDetail.status === 'loading' && !selectedDetail.previous ? <RequestState title="Loading transcript" reason="Fetching up to 80 records." /> : null}
                {selectedDetail.status === 'not-found' ? <RequestState title="Transcript not found" reason={`No public transcript matches ${selectedDetail.session}.`} /> : null}
                {selectedDetail.status === 'unavailable' || selectedDetail.status === 'error' ? <RequestBanner tone="danger" message={`${selectedDetail.message}${selectedDetail.previous ? ` Showing records updated ${formatUpdatedAt(selectedDetail.previous.updatedAt)}.` : ''}`} action="Retry" onAction={() => setDetailRetry((value) => value + 1)} /> : null}
                {detailData ? (
                  <div className="chat-transcript transcript-preview-thread" aria-label="Complete transcript conversation" tabIndex={0}>
                    {records.length > 0 ? <CodexTranscriptThread records={records} /> : selectedSession?.samples.length ? <CodexTranscriptThread records={samplesAsRecords(selectedSession.samples)} /> : <RequestState title="Metadata only" reason="This transcript has no displayable conversation records." />}
                    {detailData.hasMore || loadMore.status === 'error' ? <div className="transcript-load-more-wrap"><button className="transcript-load-more" disabled={loadMore.status === 'loading'} onClick={loadMoreTranscript} type="button">{loadMore.status === 'loading' ? 'Loading more' : loadMore.status === 'error' ? 'Retry load more' : 'Load more'}</button>{loadMore.status === 'error' ? <span role="alert">{loadMore.message}</span> : null}</div> : <span className="transcript-end-note">End of loaded transcript</span>}
                  </div>
                ) : null}
              </div>

              <footer className="transcript-viewer-foot"><span>Lines: <code>{formatInteger(detailData?.totalLines ?? selectedSession?.lines ?? 0)}</code></span><span>Displayed: <code>{formatInteger(conversationItemCount)}</code></span></footer>
              {manifest?.sources?.length ? <p className="transcript-source-note">Source: {manifest.sources.map((source) => source.note).join(' ')}</p> : null}
            </>
          )}
        </article>
      </div>
    </section>
  );
}

function Summary({ label, value }: { label: string; value: string }) {
  return <div><dt>{label}</dt><dd>{value}</dd></div>;
}

function Meta({ label, value }: { label: string; value: string }) {
  return <div><dt>{label}</dt><dd>{value || 'unknown'}</dd></div>;
}

function RequestState({ icon, title, reason, action, onAction }: { icon?: React.ReactNode; title: string; reason: string; action?: string; onAction?: () => void }) {
  return <div className="transcript-request-state">{icon}<b>{title}</b><p>{reason}</p>{action && onAction ? <button type="button" onClick={onAction}>{action}</button> : null}</div>;
}

function RequestBanner({ tone, message, action, onAction }: { tone: 'danger'; message: string; action: string; onAction: () => void }) {
  return <div className={`transcript-request-banner is-${tone}`} role="alert"><span>{message}</span><button type="button" onClick={onAction}>{action}</button></div>;
}

function currentCollection(state: CollectionState) {
  if (state.status === 'ready-empty' || state.status === 'ready-populated') return state.data;
  if (state.status === 'loading' || state.status === 'unavailable' || state.status === 'error') return state.previous;
  return undefined;
}

function currentDetail(state: DetailState) {
  if (state.status === 'ready-empty' || state.status === 'ready-populated') return state.data;
  if (state.status === 'loading' || state.status === 'unavailable' || state.status === 'error') return state.previous;
  return undefined;
}

function detailSession(state: DetailState) {
  return state.status === 'idle' ? '' : state.session;
}

function isCollectionReady(state: CollectionState) {
  return state.status === 'ready-empty' || state.status === 'ready-populated' || Boolean(currentCollection(state));
}

function samplesAsRecords(samples: TranscriptSample[]): TranscriptRecord[] {
  return samples.map((sample, index) => ({ line: index + 1, timestamp: sample.timestamp, type: 'sample', role: sample.role, payloadType: 'message', text: sample.text, eventKind: 'sample', toolName: '', toolCallId: '', textTruncated: false }));
}

function canonicalizeOwnedParams(params: URLSearchParams) {
  const owned = readOwnedParams(params);
  setOrDelete(params, 'q', owned.q);
  setOrDelete(params, 'from', owned.from);
  setOrDelete(params, 'to', owned.to);
  setCanonicalPage(params, owned.page);
  setOrDelete(params, 'session', owned.session);
}

function setCanonicalPage(params: URLSearchParams, page: number) {
  if (page <= 1) params.delete('page');
  else params.set('page', String(page));
}

function setOrDelete(params: URLSearchParams, name: string, value: string) {
  if (value) params.set(name, value);
  else params.delete(name);
}

function normalizePage(value: string | null) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? Math.max(1, Math.trunc(parsed)) : 1;
}

function normalizeDate(value: string | null | undefined) {
  if (!value || !/^\d{4}-\d{2}-\d{2}$/.test(value)) return '';
  const parsed = new Date(`${value}T00:00:00.000Z`);
  return Number.isNaN(parsed.getTime()) || parsed.toISOString().slice(0, 10) !== value ? '' : value;
}

function normalizeSession(value: string | null) {
  return value?.trim().slice(0, 512) ?? '';
}

function readScrollMap() {
  try {
    const parsed = JSON.parse(window.sessionStorage.getItem(listScrollStorageKey) ?? '{}') as unknown;
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return {} as Record<string, number>;
    return Object.fromEntries(Object.entries(parsed).filter((entry): entry is [string, number] => typeof entry[1] === 'number' && Number.isFinite(entry[1]) && entry[1] >= 0));
  } catch {
    return {} as Record<string, number>;
  }
}

function writeListScroll(key: string, value: number) {
  try {
    const map = readScrollMap();
    delete map[key];
    map[key] = Math.max(0, value);
    const entries = Object.entries(map).slice(-50);
    window.sessionStorage.setItem(listScrollStorageKey, JSON.stringify(Object.fromEntries(entries)));
  } catch {
    // Storage may be unavailable in privacy modes; navigation must still work.
  }
}

function readListScroll(key: string) {
  return readScrollMap()[key] ?? 0;
}

class RequestError extends Error {
  constructor(readonly status: number, message: string) {
    super(message);
  }
}

function formatInteger(value: number) {
  return new Intl.NumberFormat('en-US').format(value);
}

function formatBytes(bytes: number) {
  if (!bytes) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const index = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  const value = bytes / 1024 ** index;
  return `${value >= 10 || index === 0 ? value.toFixed(0) : value.toFixed(1)} ${units[index]}`;
}

function formatDateTime(value: string) {
  if (!value) return 'unknown';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return 'unknown';
  return new Intl.DateTimeFormat('en-US', { month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false, timeZone: 'UTC' }).format(date);
}

function formatUpdatedAt(value: number) {
  return new Intl.DateTimeFormat('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit' }).format(value);
}

function formatDateFilterLabel(startValue: string, endValue: string) {
  if (!startValue && !endValue) return 'All transcripts';
  const start = formatDateOnly(startValue);
  const end = formatDateOnly(endValue);
  if (start && end) return `${start} - ${end}`;
  if (start) return `From ${start}`;
  if (end) return `Through ${end}`;
  return 'All transcripts';
}

function formatDateRange(range: TranscriptManifest['dateRange']) {
  if (!range?.start && !range?.end) return 'unknown';
  const formatter = new Intl.DateTimeFormat('en-US', { month: 'short', day: '2-digit', year: 'numeric', timeZone: 'UTC' });
  const start = range.start ? new Date(range.start) : null;
  const end = range.end ? new Date(range.end) : null;
  if (start && Number.isNaN(start.getTime()) || end && Number.isNaN(end.getTime())) return 'unknown';
  if (start && end) return `${formatter.format(start)} - ${formatter.format(end)}`;
  return start ? `From ${formatter.format(start)}` : `Through ${formatter.format(end!)}`;
}

function formatDateOnly(value: string) {
  if (!value) return '';
  const date = new Date(`${value.slice(0, 10)}T00:00:00.000Z`);
  if (Number.isNaN(date.getTime())) return '';
  return new Intl.DateTimeFormat('en-US', { month: 'short', day: '2-digit', year: 'numeric', timeZone: 'UTC' }).format(date);
}

function dateRangeEndDate(range: TranscriptManifest['dateRange'] | null) {
  if (!range?.end) return null;
  const end = new Date(range.end);
  return Number.isNaN(end.getTime()) ? null : end;
}

function toDateInputValue(date: Date) {
  return date.toISOString().slice(0, 10);
}

function isDatePresetActive(days: (typeof datePresets)[number], dateFrom: string, dateTo: string, range: TranscriptManifest['dateRange'] | null) {
  const end = dateRangeEndDate(range);
  if (!end) return false;
  const start = new Date(end);
  start.setUTCDate(start.getUTCDate() - days + 1);
  return dateFrom === toDateInputValue(start) && dateTo === toDateInputValue(end);
}

function openNativeDatePicker(input: HTMLInputElement | null) {
  if (!input) return;
  input.focus();
  try { input.showPicker(); } catch { input.click(); }
}

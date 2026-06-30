'use client';

import {
  Archive,
  CalendarDays,
  ChevronDown,
  Database,
  Download,
  FileJson,
  Search,
  Terminal,
  X,
} from 'lucide-react';
import type { ReactNode } from 'react';
import { useEffect, useMemo, useRef, useState } from 'react';
import { CodexTranscriptThread, transcriptDisplayCount } from '@/components/codex-transcript-thread';
import type { TranscriptRecord, TranscriptRole } from '@/lib/codex-transcript';

interface TranscriptSample {
  role: TranscriptRole;
  timestamp: string;
  phase: string;
  text: string;
}

interface TranscriptSession {
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

interface TranscriptManifest {
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
  dateRange?: {
    start: string;
    end: string;
  };
  sources?: {
    name: string;
    href: string;
    note: string;
  }[];
}

interface TranscriptSearchResponse {
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

interface TranscriptSessionDetail {
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

const datePresets = [7, 30, 90] as const;
const transcriptPageSize = 25;
const transcriptChunkSize = 80;
export function TranscriptDataset() {
  const [manifest, setManifest] = useState<TranscriptManifest | null>(null);
  const [datasetDateRange, setDatasetDateRange] = useState<TranscriptManifest['dateRange'] | null>(null);
  const [sessions, setSessions] = useState<TranscriptSession[]>([]);
  const [query, setQuery] = useState('');
  const [dateFrom, setDateFrom] = useState('');
  const [dateTo, setDateTo] = useState('');
  const [datePickerOpen, setDatePickerOpen] = useState(false);
  const [selectedId, setSelectedId] = useState('');
  const [page, setPage] = useState(1);
  const [pageDraft, setPageDraft] = useState('1');
  const [total, setTotal] = useState(0);
  const [totalPages, setTotalPages] = useState(1);
  const [loading, setLoading] = useState(true);
  const [detail, setDetail] = useState<TranscriptSessionDetail | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [moreLoading, setMoreLoading] = useState(false);
  const datePickerRef = useRef<HTMLDivElement>(null);
  const dateFromInputRef = useRef<HTMLInputElement>(null);
  const dateToInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    setPage(1);
  }, [dateFrom, dateTo, query]);

  useEffect(() => {
    setPageDraft(String(page));
  }, [page]);

  useEffect(() => {
    const controller = new AbortController();
    const params = new URLSearchParams({
      page: String(page),
    });
    if (query.trim()) params.set('q', query.trim());
    if (dateFrom) params.set('from', dateFrom);
    if (dateTo) params.set('to', dateTo);

    setLoading(true);

    fetch(`/transcript/api/search?${params.toString()}`, { signal: controller.signal })
      .then((response) => {
        if (!response.ok) throw new Error(`Transcript search returned ${response.status}`);
        return response.json() as Promise<TranscriptSearchResponse>;
      })
      .then((result) => {
        setManifest(result.manifest);
        if (!query.trim() && !dateFrom && !dateTo && result.manifest.dateRange) {
          setDatasetDateRange(result.manifest.dateRange);
        }
        setSessions(result.sessions);
        setPage(result.page);
        setTotal(result.total);
        setTotalPages(result.totalPages);
        setSelectedId((current) => {
          if (result.sessions.some((session) => session.id === current)) return current;
          return result.sessions[0]?.id ?? '';
        });
      })
      .catch((error: unknown) => {
        if (error instanceof DOMException && error.name === 'AbortError') return;
        setManifest({
          generatedAt: '',
          archive: 'codex-history-coquic-transcripts-only-20260630.zip',
          archiveUrl: '/dataset/codex-history-coquic-transcripts-only-20260630.zip',
          archiveBytes: 0,
          transcriptCount: 0,
          totalBytes: 0,
          totalLines: 0,
          totalMessages: 0,
          totalUserMessages: 0,
          totalAssistantMessages: 0,
          totalToolCalls: 0,
          totalTokens: 0,
        });
        setSessions([]);
        setTotal(0);
        setTotalPages(1);
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false);
      });

    return () => {
      controller.abort();
    };
  }, [dateFrom, dateTo, page, query]);

  useEffect(() => {
    if (!datePickerOpen) return;

    function handlePointerDown(event: PointerEvent) {
      if (!datePickerRef.current?.contains(event.target as Node)) {
        setDatePickerOpen(false);
      }
    }

    function handleKeyDown(event: KeyboardEvent) {
      if (event.key === 'Escape') setDatePickerOpen(false);
    }

    document.addEventListener('pointerdown', handlePointerDown);
    document.addEventListener('keydown', handleKeyDown);
    return () => {
      document.removeEventListener('pointerdown', handlePointerDown);
      document.removeEventListener('keydown', handleKeyDown);
    };
  }, [datePickerOpen]);

  const selectedSession = useMemo(
    () => sessions.find((session) => session.id === selectedId) ?? sessions[0] ?? null,
    [selectedId, sessions],
  );
  const datePresetBase = datasetDateRange ?? manifest?.dateRange ?? null;
  const visibleStart = total === 0 ? 0 : (page - 1) * transcriptPageSize + 1;
  const visibleEnd = Math.min(total, (page - 1) * transcriptPageSize + sessions.length);

  useEffect(() => {
    if (!selectedSession) {
      setSelectedId('');
      return;
    }
    if (selectedSession.id !== selectedId) {
      setSelectedId(selectedSession.id);
    }
  }, [selectedId, selectedSession]);

  useEffect(() => {
    if (!selectedSession) {
      setDetail(null);
      return;
    }
    const controller = new AbortController();
    setDetailLoading(true);
    const params = new URLSearchParams({ limit: String(transcriptChunkSize) });
    fetch(`/transcript/api/session/${encodeURIComponent(selectedSession.id)}?${params.toString()}`, { signal: controller.signal })
      .then((response) => {
        if (!response.ok) throw new Error(`Transcript session returned ${response.status}`);
        return response.json() as Promise<TranscriptSessionDetail>;
      })
      .then((nextDetail) => {
        setDetail(nextDetail);
      })
      .catch((error: unknown) => {
        if (error instanceof DOMException && error.name === 'AbortError') return;
        setDetail(null);
      })
      .finally(() => {
        if (!controller.signal.aborted) setDetailLoading(false);
      });

    return () => {
      controller.abort();
    };
  }, [selectedSession]);

  const conversationRecords = useMemo(() => detail?.records ?? [], [detail]);
  const conversationItemCount = useMemo(() => transcriptDisplayCount(conversationRecords), [conversationRecords]);

  function loadMoreTranscript() {
    if (!selectedSession || !detail || moreLoading || !detail.hasMore) return;
    const params = new URLSearchParams({
      cursor: String(detail.nextCursor),
      limit: String(transcriptChunkSize),
    });
    setMoreLoading(true);
    fetch(`/transcript/api/session/${encodeURIComponent(selectedSession.id)}?${params.toString()}`)
      .then((response) => {
        if (!response.ok) throw new Error(`Transcript session returned ${response.status}`);
        return response.json() as Promise<TranscriptSessionDetail>;
      })
      .then((nextDetail) => {
        setDetail((current) => {
          if (!current || current.sessionId !== nextDetail.sessionId) return nextDetail;
          return {
            ...nextDetail,
            records: [...current.records, ...nextDetail.records],
          };
        });
      })
      .catch(() => {
        // The selected transcript remains readable even if a later page fails.
      })
      .finally(() => {
        setMoreLoading(false);
      });
  }

  function commitPageDraft() {
    const parsed = Number(pageDraft);
    if (!Number.isFinite(parsed)) {
      setPageDraft(String(page));
      return;
    }
    const nextPage = Math.min(totalPages, Math.max(1, Math.trunc(parsed)));
    setPage(nextPage);
    setPageDraft(String(nextPage));
  }

  function applyDatePreset(days: (typeof datePresets)[number]) {
    const end = dateRangeEndDate(datePresetBase) ?? new Date();
    const start = new Date(end);
    start.setUTCDate(start.getUTCDate() - days + 1);
    setDateFrom(toDateInputValue(start));
    setDateTo(toDateInputValue(end));
    setDatePickerOpen(false);
  }

  function clearDateFilter() {
    setDateFrom('');
    setDateTo('');
    setDatePickerOpen(false);
  }

  function openNativeDatePicker(input: HTMLInputElement | null) {
    if (!input) return;
    input.focus();
    try {
      input.showPicker();
    } catch {
      // Some browsers only allow focus/click behavior for date inputs.
      input.click();
    }
  }

  if (!manifest) {
    return (
      <section className="transcript-loading" aria-label="Transcript dataset loading">
        <Database aria-hidden="true" />
        <span>Loading transcript dataset</span>
      </section>
    );
  }

  return (
    <section className="transcript-shell" aria-labelledby="transcript-title">
      <header className="transcript-hero">
        <div className="transcript-hero-copy">
          <span className="transcript-eyebrow">
            <Database aria-hidden="true" />
            Public dataset
          </span>
          <h1 id="transcript-title">CoQUIC Transcript Dataset</h1>
          <p>
            Development transcripts from the Codex sessions that built CoQUIC, indexed for browsing and available as raw JSONL.
          </p>
        </div>
        {manifest.archiveBytes > 0 ? (
          <a className="transcript-download" href={manifest.archiveUrl} download>
            <Download aria-hidden="true" />
            <span>Download dataset</span>
            <small>{formatBytes(manifest.archiveBytes)}</small>
          </a>
        ) : (
          <span className="transcript-download transcript-download-disabled" aria-disabled="true">
            <Download aria-hidden="true" />
            <span>Dataset unavailable</span>
            <small>Archive missing</small>
          </span>
        )}
      </header>

      <div className="transcript-stats" aria-label="Dataset summary">
        <Metric icon={<FileJson aria-hidden="true" />} label="Transcripts" value={formatInteger(manifest.transcriptCount)} />
        <Metric icon={<CalendarDays aria-hidden="true" />} label="Date range" value={formatDateRange(manifest.dateRange)} />
        <Metric icon={<Archive aria-hidden="true" />} label="Total tokens" value={formatCompactInteger(manifest.totalTokens)} />
        <Metric icon={<Terminal aria-hidden="true" />} label="Tool calls" value={formatInteger(manifest.totalToolCalls)} />
      </div>

      <div className="transcript-controls" aria-label="Transcript filters">
        <label className="transcript-search">
          <Search aria-hidden="true" />
          <input
            value={query}
            onChange={(event) => {
              setQuery(event.target.value);
            }}
            aria-label="Search transcript sessions"
            placeholder="Search titles, paths, session IDs"
            type="search"
          />
        </label>
        <div className="transcript-date-filter" data-open={datePickerOpen ? 'true' : undefined} ref={datePickerRef}>
          <button
            className="transcript-date-trigger"
            type="button"
            aria-expanded={datePickerOpen}
            aria-haspopup="dialog"
            onClick={() => {
              setDatePickerOpen((open) => !open);
            }}
          >
            <CalendarDays aria-hidden="true" />
            <span>
              <small>Date range</small>
              <b>{formatDateFilterLabel(dateFrom, dateTo)}</b>
            </span>
            <ChevronDown aria-hidden="true" />
          </button>
          {dateFrom || dateTo ? (
            <button className="transcript-date-clear" type="button" aria-label="Clear date filter" onClick={clearDateFilter}>
              <X aria-hidden="true" />
            </button>
          ) : null}
          {datePickerOpen ? (
            <div className="transcript-date-panel" role="dialog" aria-label="Transcript date range">
              <div className="transcript-date-presets" role="group" aria-label="Quick date ranges">
                <button type="button" data-active={!dateFrom && !dateTo ? 'true' : undefined} onClick={clearDateFilter}>
                  All
                </button>
                {datePresets.map((days) => (
                  <button
                    key={days}
                    type="button"
                    data-active={isDatePresetActive(days, dateFrom, dateTo, datePresetBase) ? 'true' : undefined}
                    onClick={() => {
                      applyDatePreset(days);
                    }}
                  >
                    {days}D
                  </button>
                ))}
              </div>
              <div className="transcript-date-fields">
                <label>
                  <span className="transcript-date-field-label">From</span>
                  <span className="transcript-date-input-shell">
                    <input
                      aria-label="Filter transcripts from date"
                      max={dateTo || undefined}
                      onChange={(event) => {
                        setDateFrom(event.target.value);
                      }}
                      ref={dateFromInputRef}
                      type="date"
                      value={dateFrom}
                    />
                    <button
                      type="button"
                      aria-label="Open from-date calendar"
                      onClick={() => {
                        openNativeDatePicker(dateFromInputRef.current);
                      }}
                    >
                      <CalendarDays aria-hidden="true" />
                    </button>
                  </span>
                </label>
                <label>
                  <span className="transcript-date-field-label">To</span>
                  <span className="transcript-date-input-shell">
                    <input
                      aria-label="Filter transcripts to date"
                      min={dateFrom || undefined}
                      onChange={(event) => {
                        setDateTo(event.target.value);
                      }}
                      ref={dateToInputRef}
                      type="date"
                      value={dateTo}
                    />
                    <button
                      type="button"
                      aria-label="Open to-date calendar"
                      onClick={() => {
                        openNativeDatePicker(dateToInputRef.current);
                      }}
                    >
                      <CalendarDays aria-hidden="true" />
                    </button>
                  </span>
                </label>
              </div>
            </div>
          ) : null}
        </div>
      </div>

      <div className="transcript-workspace">
        <aside className="transcript-list" aria-label="Transcript sessions">
          <div className="transcript-list-head">
            <b>{formatInteger(total)} sessions</b>
            <span>
              {formatInteger(visibleStart)}-{formatInteger(visibleEnd)}
            </span>
          </div>
          {loading ? (
            <div className="transcript-empty">Loading sessions.</div>
          ) : sessions.length === 0 ? (
            <div className="transcript-empty">No transcript matches the current filters.</div>
          ) : (
            sessions.map((session) => (
              <button
                key={session.id}
                type="button"
                className="transcript-row"
                data-active={selectedSession?.id === session.id ? 'true' : undefined}
                onClick={() => {
                  setSelectedId(session.id);
                }}
              >
                <span className="transcript-row-top">
                  <b>{session.title}</b>
                  <small>{formatBytes(session.bytes)}</small>
                </span>
                <span className="transcript-row-preview">{session.preview}</span>
                <span className="transcript-row-meta">
                  <span>{formatDateTime(session.startedAt)}</span>
                </span>
              </button>
            ))
          )}
          <div className="transcript-pagination" aria-label="Transcript pages">
            <button
              type="button"
              disabled={page <= 1 || loading}
              onClick={() => {
                setPage((current) => Math.max(1, current - 1));
              }}
            >
              Previous
            </button>
            <label className="transcript-page-jump">
              <span>Page</span>
              <input
                value={pageDraft}
                aria-label={`Jump to transcript page, 1 through ${totalPages}`}
                inputMode="numeric"
                min={1}
                max={totalPages}
                type="number"
                disabled={loading || totalPages <= 1}
                onBlur={commitPageDraft}
                onChange={(event) => {
                  setPageDraft(event.target.value);
                }}
                onKeyDown={(event) => {
                  if (event.key === 'Enter') {
                    event.currentTarget.blur();
                  }
                }}
              />
              <span>of {formatInteger(totalPages)}</span>
            </label>
            <button
              type="button"
              disabled={page >= totalPages || loading}
              onClick={() => {
                setPage((current) => Math.min(totalPages, current + 1));
              }}
            >
              Next
            </button>
          </div>
        </aside>

        <article className="transcript-viewer" aria-label="Selected transcript preview">
          {selectedSession ? (
            <>
              <header className="transcript-viewer-head">
                <div>
                  <h2>{selectedSession.title}</h2>
                  <p>{selectedSession.preview}</p>
                </div>
                <div className="transcript-download-actions">
                  <a className="transcript-archive-member" href={`/transcript/api/session/${encodeURIComponent(selectedSession.id)}/raw`} download>
                    <FileJson aria-hidden="true" />
                    <span>JSONL</span>
                  </a>
                  <a className="transcript-archive-member" href={manifest.archiveUrl} download>
                    <Download aria-hidden="true" />
                    <span>ZIP</span>
                  </a>
                </div>
              </header>

              <dl className="transcript-meta-grid">
                <Meta label="Started" value={formatDateTime(selectedSession.startedAt)} />
                <Meta label="Session ID" value={selectedSession.sessionId} />
                <Meta label="Source" value={[selectedSession.originator, selectedSession.source].filter(Boolean).join(' / ')} />
                <Meta label="CLI" value={selectedSession.cliVersion || 'unknown'} />
              </dl>

              {detailLoading ? (
                <div className="transcript-empty">Loading transcript preview.</div>
              ) : (
                <div className="chat-transcript transcript-preview-thread" aria-label="Complete transcript conversation">
                  {conversationRecords.length > 0 ? (
                    <CodexTranscriptThread records={conversationRecords} />
                  ) : selectedSession.samples.length > 0 ? (
                    <CodexTranscriptThread
                      records={selectedSession.samples.map((sample, index) => ({
                        line: index + 1,
                        timestamp: sample.timestamp,
                        type: 'sample',
                        role: sample.role,
                        payloadType: 'message',
                        text: sample.text,
                        eventKind: 'sample',
                        toolName: '',
                        toolCallId: '',
                        textTruncated: false,
                      }))}
                    />
                  ) : (
                    <div className="transcript-empty">This transcript contains session metadata only.</div>
                  )}
                  {detail?.hasMore ? (
                    <button className="transcript-load-more" disabled={moreLoading} onClick={loadMoreTranscript} type="button">
                      {moreLoading ? 'Loading more' : 'Load more'}
                    </button>
                  ) : null}
                </div>
              )}

              <footer className="transcript-viewer-foot">
                <span>
                  Lines: <code>{formatInteger(detail?.totalLines ?? selectedSession.lines)}</code>
                </span>
                <span>
                  Displayed: <code>{formatInteger(conversationItemCount)}</code>
                </span>
              </footer>
            </>
          ) : (
            <div className="transcript-empty">No transcript dataset is available.</div>
          )}
        </article>
      </div>
    </section>
  );
}

function Metric({ icon, label, value }: { icon: ReactNode; label: string; value: string }) {
  return (
    <div className="transcript-metric">
      {icon}
      <span>{label}</span>
      <b>{value}</b>
    </div>
  );
}

function Meta({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <dt>{label}</dt>
      <dd>{value || 'unknown'}</dd>
    </div>
  );
}

function formatInteger(value: number) {
  return new Intl.NumberFormat('en-US').format(value);
}

function formatCompactInteger(value: number) {
  return new Intl.NumberFormat('en-US', {
    notation: 'compact',
    maximumFractionDigits: 1,
  }).format(value);
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
  return new Intl.DateTimeFormat('en-US', {
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
    timeZone: 'UTC',
  }).format(date);
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
  const formatter = new Intl.DateTimeFormat('en-US', {
    month: 'short',
    day: '2-digit',
    timeZone: 'UTC',
  });
  if (range.start && !range.end) {
    const start = new Date(range.start);
    return Number.isNaN(start.getTime()) ? 'unknown' : `From ${formatter.format(start)}`;
  }
  if (!range.start && range.end) {
    const end = new Date(range.end);
    return Number.isNaN(end.getTime()) ? 'unknown' : `Through ${formatter.format(end)}`;
  }
  const start = new Date(range.start);
  const end = new Date(range.end);
  if (Number.isNaN(start.getTime()) || Number.isNaN(end.getTime())) return 'unknown';
  return `${formatter.format(start)}-${formatter.format(end)}`;
}

function formatDateOnly(value: string) {
  if (!value) return '';
  const date = new Date(`${value.slice(0, 10)}T00:00:00.000Z`);
  if (Number.isNaN(date.getTime())) return '';
  return new Intl.DateTimeFormat('en-US', {
    month: 'short',
    day: '2-digit',
    year: 'numeric',
    timeZone: 'UTC',
  }).format(date);
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

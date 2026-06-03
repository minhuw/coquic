'use client';

import { useEffect, useMemo, useRef, useState } from 'react';
import type { Dispatch, MutableRefObject, SetStateAction } from 'react';
import { Check, Copy, TriangleAlert } from 'lucide-react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';

import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';

interface Usage {
  prompt_tokens?: number | null;
  completion_tokens?: number | null;
  total_tokens?: number | null;
}

interface Citation {
  citation?: string | null;
  doc_id?: string | null;
  section_id?: string | null;
  title?: string | null;
  score?: number | null;
  text?: string | null;
  url?: string | null;
}

interface QaPayload {
  answer: string;
  accepted: boolean;
  reason: string;
  citations?: Citation[];
  usage?: Usage | null;
  rag_confidence?: number | null;
  direct_answer?: string | null;
  direct_usage?: Usage | null;
  direct_model?: string | null;
  rag_answer?: string | null;
  rag_usage?: Usage | null;
  rag_model?: string | null;
}

interface StreamHandlers {
  onMetadata(payload: Partial<QaPayload>): void;
  onDirect(payload: StreamChunkPayload): void;
  onRag(payload: StreamChunkPayload): void;
  onDone(payload: QaPayload): void;
}

interface StreamChunkPayload {
  delta?: string;
  usage?: Usage | null;
  model?: string | null;
  done?: boolean;
}

interface StreamMetrics {
  firstTokenMs: number | null;
  lastTokenMs: number | null;
  completionTokens: number | null;
}

interface ModelMeta {
  provider: string;
  size: string;
  avatar: string;
  swatch: string;
  label?: string;
  iconSrc?: string;
}

const apiBase = '/rag-api';
const qaModel = 'deepseek-v4-pro';
const storageNames = {
  qaSession: 'coquic-qa-session',
} as const;

export function QaClient() {
  const [question, setQuestion] = useState('');
  const [status, setStatus] = useState('ready');
  const [busy, setBusy] = useState(false);
  const [suggesting, setSuggesting] = useState(false);
  const [directAnswer, setDirectAnswer] = useState('');
  const [ragAnswer, setRagAnswer] = useState('');
  const [directUsage, setDirectUsage] = useState<Usage | null>(null);
  const [ragUsage, setRagUsage] = useState<Usage | null>(null);
  const [directMetrics, setDirectMetrics] = useState<StreamMetrics>(emptyStreamMetrics);
  const [ragMetrics, setRagMetrics] = useState<StreamMetrics>(emptyStreamMetrics);
  const [directModel, setDirectModel] = useState('');
  const [ragModel, setRagModel] = useState('');
  const [queryStartedAt, setQueryStartedAt] = useState<number | null>(null);
  const [queryElapsedMs, setQueryElapsedMs] = useState<number | null>(null);
  const [ragConfidence, setRagConfidence] = useState<number | null>(null);
  const [citations, setCitations] = useState<Citation[]>([]);
  const [questionError, setQuestionError] = useState('');
  const suggestRequestId = useRef(0);
  const directMetricsRef = useRef<StreamMetrics>(emptyStreamMetrics());
  const ragMetricsRef = useRef<StreamMetrics>(emptyStreamMetrics());

  const hasResults = directAnswer.length > 0 || ragAnswer.length > 0;
  const hasCitations = citations.length > 0;
  const sessionId = useMemo(() => getSessionId(), []);

  useEffect(() => {
    if (!busy || queryStartedAt === null) {
      return;
    }

    const updateElapsed = () => {
      setQueryElapsedMs(Date.now() - queryStartedAt);
    };
    updateElapsed();
    const intervalId = window.setInterval(updateElapsed, 250);
    return () => {
      window.clearInterval(intervalId);
    };
  }, [busy, queryStartedAt]);

  async function submit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const trimmed = question.trim();
    if (!trimmed) {
      return;
    }

    const startedAt = Date.now();
    setBusy(true);
    setStatus('asking');
    setQueryStartedAt(startedAt);
    setQueryElapsedMs(0);
    setDirectAnswer('Asking DeepSeek V4 Pro directly...');
    setRagAnswer('Retrieving QUIC context...');
    setDirectUsage(null);
    setRagUsage(null);
    directMetricsRef.current = emptyStreamMetrics();
    ragMetricsRef.current = emptyStreamMetrics();
    setDirectMetrics(directMetricsRef.current);
    setRagMetrics(ragMetricsRef.current);
    setDirectModel(qaModel);
    setRagModel(qaModel);
    setRagConfidence(null);
    setCitations([]);

    try {
      await askStream(trimmed, sessionId, {
        onMetadata: (payload) => {
          setCitations(payload.citations ?? []);
          setRagConfidence(typeof payload.rag_confidence === 'number' ? payload.rag_confidence : null);
        },
        onDirect: (payload) => {
          recordStreamMetrics(payload, startedAt, directMetricsRef, setDirectMetrics);
          setDirectAnswer((current) => appendStreamText(current, payload.delta ?? ''));
          if (payload.usage) {
            setDirectUsage(payload.usage);
          }
          if (payload.model) {
            setDirectModel(payload.model);
          }
        },
        onRag: (payload) => {
          recordStreamMetrics(payload, startedAt, ragMetricsRef, setRagMetrics);
          setRagAnswer((current) => appendStreamText(current, payload.delta ?? ''));
          if (payload.usage) {
            setRagUsage(payload.usage);
          }
          if (payload.model) {
            setRagModel(payload.model);
          }
        },
        onDone: (payload) => {
          recordStreamUsage(payload.direct_usage ?? null, startedAt, directMetricsRef, setDirectMetrics);
          recordStreamUsage(payload.rag_usage ?? payload.usage ?? null, startedAt, ragMetricsRef, setRagMetrics);
          setDirectAnswer(payload.direct_answer ?? payload.answer ?? 'No direct answer returned.');
          setRagAnswer(payload.rag_answer ?? payload.answer ?? 'No RAG answer returned.');
          setDirectUsage(payload.direct_usage ?? null);
          setRagUsage(payload.rag_usage ?? payload.usage ?? null);
          setDirectModel(payload.direct_model ?? qaModel);
          setRagModel(payload.rag_model ?? qaModel);
          setRagConfidence(typeof payload.rag_confidence === 'number' ? payload.rag_confidence : null);
          setCitations(payload.citations ?? []);
          setStatus(publicStatus(payload));
        },
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : 'request failed';
      setDirectAnswer(message);
      setRagAnswer(message);
      setDirectUsage(null);
      setRagUsage(null);
      directMetricsRef.current = emptyStreamMetrics();
      ragMetricsRef.current = emptyStreamMetrics();
      setDirectMetrics(directMetricsRef.current);
      setRagMetrics(ragMetricsRef.current);
      setDirectModel(qaModel);
      setRagModel(qaModel);
      setRagConfidence(null);
      setCitations([]);
      setStatus('error');
    } finally {
      setQueryElapsedMs(Date.now() - startedAt);
      setQueryStartedAt(null);
      setBusy(false);
    }
  }

  async function suggestQuestion() {
    const requestId = suggestRequestId.current + 1;
    suggestRequestId.current = requestId;
    setSuggesting(true);
    setQuestionError('');
    setStatus('generating question');
    try {
      const payload = await randomQuestion(sessionId);
      if (requestId !== suggestRequestId.current) {
        return;
      }
      setQuestion(payload.question);
      setQuestionError('');
      setStatus('question generated');
    } catch (error) {
      if (requestId !== suggestRequestId.current) {
        return;
      }
      const message = error instanceof Error ? error.message : 'request failed';
      setQuestionError(
        message === 'rate limit exceeded'
          ? 'Random question limit reached. Try again in a minute.'
          : 'Random question generation is temporarily unavailable.',
      );
      setStatus(message);
    } finally {
      if (requestId === suggestRequestId.current) {
        setSuggesting(false);
      }
    }
  }

  return (
    <section className="mt-5 grid gap-3" aria-label="Ask QUIC specification questions">
      <Card>
        <CardContent>
          <form className="grid gap-3" onSubmit={(event) => void submit(event)}>
            <label className="sr-only" htmlFor="qa-question">
              Question
            </label>
            <textarea
              className="min-h-40 w-full resize-y rounded-[var(--radius)] border border-[var(--line-strong)] bg-[var(--surface)] p-3 text-sm leading-relaxed text-[var(--ink)] outline-none focus:border-[var(--primary)] focus:ring-2 focus:ring-[rgba(15,98,254,0.24)]"
              id="qa-question"
              name="question"
              maxLength={1200}
              rows={5}
              required
              value={question}
              onChange={(event) => {
                setQuestion(event.target.value);
              }}
              onKeyDown={(event) => {
                if (event.key === 'Enter' && event.ctrlKey) {
                  event.preventDefault();
                  event.currentTarget.form?.requestSubmit();
                }
              }}
              placeholder="How does QUIC ACK delay affect loss recovery?"
            />
            <div className="flex items-center justify-between gap-3">
              <span className="flex min-w-0 flex-wrap items-center gap-2">
                <span className="inline-flex h-9 shrink-0 items-center gap-2 text-xs font-medium text-[var(--muted)]">
                  <span>Powered by DeepSeek V4 Pro</span>
                  <img className="size-9" src="/deepseek-logo-icon.svg" alt="" aria-hidden="true" />
                  <PrivacyNotice />
                </span>
              </span>
              <span className="inline-flex shrink-0 items-center gap-2">
                <Button type="button" variant="outline" disabled={busy || suggesting} onClick={suggestQuestion}>
                  {suggesting ? 'Generating' : 'Random'}
                </Button>
                <Button type="submit" disabled={busy || suggesting}>
                  Ask
                </Button>
              </span>
            </div>
            <span className="sr-only" aria-live="polite">
              {status}
            </span>
            {questionError ? (
              <p className="text-sm text-[var(--danger)]" aria-live="polite">
                {questionError}
              </p>
            ) : null}
          </form>
        </CardContent>
      </Card>

      {hasResults ? (
        <div className="grid min-w-0 gap-3 lg:grid-cols-2">
          <Card className="min-w-0 min-h-[280px]">
            <AnswerHeader
              answer={directAnswer}
              busy={busy}
              copyLabel="direct answer"
              elapsedMs={queryElapsedMs}
              metrics={directMetrics}
              model={directModel || qaModel}
              title="Direct"
              usage={directUsage}
            />
            <CardContent className="min-w-0">
              <MarkdownAnswer>{directAnswer}</MarkdownAnswer>
            </CardContent>
          </Card>

          <Card className="min-w-0 min-h-[280px]">
            <AnswerHeader
              answer={ragAnswer}
              busy={busy}
              confidence={ragConfidence}
              copyLabel="RAG answer"
              elapsedMs={queryElapsedMs}
              metrics={ragMetrics}
              model={ragModel || qaModel}
              title="With RAG"
              usage={ragUsage}
            />
            <CardContent className="grid min-w-0 gap-4">
              <MarkdownAnswer>{ragAnswer}</MarkdownAnswer>
              {hasCitations ? <Citations citations={citations} /> : null}
            </CardContent>
          </Card>
        </div>
      ) : null}
    </section>
  );
}

function AnswerHeader({
  answer,
  busy,
  confidence,
  copyLabel,
  elapsedMs,
  metrics,
  model,
  title,
  usage,
}: {
  answer: string;
  busy: boolean;
  confidence?: number | null;
  copyLabel: string;
  elapsedMs: number | null;
  metrics: StreamMetrics;
  model: string;
  title: string;
  usage: Usage | null;
}) {
  return (
    <CardHeader className="grid gap-2">
      <div className="grid min-w-0 grid-cols-[auto_minmax(0,1fr)] items-center gap-3">
        <span className="flex min-w-0 items-center gap-2">
          <CardTitle>{title}</CardTitle>
          <CopyAnswerButton answer={answer} disabled={busy} label={copyLabel} />
        </span>
        <span className="flex min-w-0 justify-end">
          <ModelBadge model={model} />
        </span>
      </div>
      <div className="grid min-w-0 grid-cols-[auto_minmax(0,1fr)] items-center gap-3">
        <span aria-hidden="true" className="min-h-[22px]" />
        <span className="flex min-w-0 flex-wrap items-center justify-end gap-1.5">
          <FirstTokenBadge metrics={metrics} />
          <TokenSpeedBadge answer={answer} metrics={metrics} />
          <ElapsedBadge elapsedMs={elapsedMs} />
          <UsageBadge usage={usage} />
          <ConfidenceBadge confidence={confidence ?? null} />
        </span>
      </div>
    </CardHeader>
  );
}

function PrivacyNotice() {
  return (
    <span className="group relative inline-flex items-center">
      <button
        aria-label="Privacy notice"
        className="inline-flex size-5 items-center justify-center rounded-full text-[var(--muted)] transition-colors duration-200 hover:bg-[var(--warning-soft)] hover:text-[var(--warning)] focus-visible:bg-[var(--warning-soft)] focus-visible:text-[var(--warning)] focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[rgba(141,109,0,0.32)]"
        type="button"
      >
        <TriangleAlert aria-hidden="true" className="size-3.5" />
      </button>
      <span
        className="theme-popover pointer-events-none absolute bottom-[calc(100%+10px)] right-0 z-40 w-[min(82vw,340px)] rounded-[var(--radius)] border border-[rgba(141,109,0,0.22)] bg-[var(--warning-tooltip)] p-3 text-left text-xs font-normal leading-relaxed text-[var(--ink)] opacity-0 transition-opacity duration-150 group-focus-within:opacity-100 group-hover:opacity-100"
        role="tooltip"
      >
        CoQUIC does not store your questions or generated answers. DeepSeek V4 Pro processes QA requests; refer to
        DeepSeek's privacy policy for how DeepSeek handles submitted data.
      </span>
    </span>
  );
}

function ModelAvatar({ meta }: { meta: ModelMeta }) {
  if (meta.iconSrc) {
    return (
      <span className="inline-flex size-7 shrink-0 items-center justify-center rounded-[var(--radius)] border border-[var(--line)] bg-[var(--surface)] p-1">
        <img alt="" aria-hidden="true" className="size-full object-contain" src={meta.iconSrc} />
      </span>
    );
  }

  return (
    <span
      className="inline-flex size-7 shrink-0 items-center justify-center rounded-[var(--radius)] font-mono text-[11px] font-black text-white"
      style={{ background: meta.swatch }}
    >
      {meta.avatar}
    </span>
  );
}

function ModelBadge({ model }: { model: string }) {
  return (
    <span className="min-w-0 truncate rounded-[var(--radius)] border border-[var(--line)] bg-[var(--surface-2)] px-2 py-1 font-mono text-[11px] leading-none text-[var(--muted)]">
      {displayModel(model)}
    </span>
  );
}

function ElapsedBadge({ elapsedMs }: { elapsedMs: number | null }) {
  if (elapsedMs === null) {
    return null;
  }

  return (
    <span
      aria-label={`Query elapsed time ${formatElapsed(elapsedMs)}`}
      className="shrink-0 rounded-[var(--radius)] border border-[var(--line)] bg-[var(--surface-2)] px-2 py-1 font-mono text-[11px] leading-none text-[var(--muted)]"
    >
      {formatElapsed(elapsedMs)}
    </span>
  );
}

function FirstTokenBadge({ metrics }: { metrics: StreamMetrics }) {
  if (metrics.firstTokenMs === null) {
    return null;
  }

  return (
    <span
      aria-label={`Time to first token ${formatElapsed(metrics.firstTokenMs)}`}
      className="shrink-0 rounded-[var(--radius)] border border-[var(--line)] bg-[var(--surface-2)] px-2 py-1 font-mono text-[11px] leading-none text-[var(--muted)]"
      title="Time from request submission to the first streamed answer token"
    >
      TTFT {formatElapsed(metrics.firstTokenMs)}
    </span>
  );
}

function TokenSpeedBadge({ answer, metrics }: { answer: string; metrics: StreamMetrics }) {
  const speed = tokenSpeed(metrics, answer);
  if (speed === null) {
    return null;
  }

  const label = `${speed.estimated ? '~' : ''}${formatTokenSpeed(speed.tokensPerSecond)}`;
  return (
    <span
      aria-label={`Token speed ${label}`}
      className="shrink-0 rounded-[var(--radius)] border border-[var(--line)] bg-[var(--surface-2)] px-2 py-1 font-mono text-[11px] leading-none text-[var(--muted)]"
      title={
        speed.estimated
          ? 'Estimated from streamed text because provider usage is not available yet'
          : 'Completion tokens divided by streamed generation time'
      }
    >
      {label}
    </span>
  );
}

function UsageBadge({ usage }: { usage: Usage | null }) {
  if (!usage) {
    return null;
  }

  const tokens = usage.total_tokens;
  if (typeof tokens !== 'number') {
    return null;
  }

  return (
    <span
      aria-label={`Token usage ${formatTokens(tokens)}`}
      className="shrink-0 rounded-[var(--radius)] border border-[var(--line)] bg-[var(--surface-2)] px-2 py-1 font-mono text-[11px] leading-none text-[var(--muted)]"
      title={formatUsageTitle(usage)}
    >
      {formatTokens(tokens)}
    </span>
  );
}

function ConfidenceBadge({ confidence }: { confidence: number | null }) {
  if (confidence === null) {
    return null;
  }

  const bounded = Math.max(0, Math.min(1, confidence));
  const label = confidenceLabel(bounded);
  return (
    <span
      aria-label={`RAG confidence ${Math.round(bounded * 100)} percent, ${label}`}
      className={`shrink-0 rounded-[var(--radius)] border px-2 py-1 font-mono text-[11px] leading-none ${confidenceClassName(bounded)}`}
      title="RAG confidence is based on retrieved section similarity scores after low-score results are filtered."
    >
      {label} {Math.round(bounded * 100)}%
    </span>
  );
}

function CopyAnswerButton({ answer, disabled, label }: { answer: string; disabled: boolean; label: string }) {
  const [copied, setCopied] = useState(false);
  const copyDisabled = disabled || !answer.trim();

  async function copyAnswer() {
    if (copyDisabled) {
      return;
    }
    await window.navigator.clipboard.writeText(answer);
    setCopied(true);
    window.setTimeout(() => {
      setCopied(false);
    }, 1600);
  }

  return (
    <button
      aria-label={copied ? `Copied ${label}` : `Copy ${label}`}
      className="inline-flex size-[22px] shrink-0 items-center justify-center rounded-[var(--radius)] border border-[var(--line)] bg-[var(--surface-2)] p-0 text-[var(--muted)] transition-colors duration-200 hover:border-[var(--primary)] hover:bg-[var(--primary-soft)] hover:text-[var(--primary)] focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[rgba(15,98,254,0.48)] disabled:pointer-events-none disabled:opacity-55"
      disabled={copyDisabled}
      onClick={() => void copyAnswer()}
      title={copied ? 'Copied' : 'Copy answer'}
      type="button"
    >
      {copied ? <Check aria-hidden="true" className="size-3.5" /> : <Copy aria-hidden="true" className="size-3.5" />}
    </button>
  );
}

function MarkdownAnswer({ children }: { children: string }) {
  return (
    <div className="qa-markdown">
      <ReactMarkdown remarkPlugins={[remarkGfm]}>{children}</ReactMarkdown>
    </div>
  );
}

function Citations({ citations }: { citations: Citation[] }) {
  return (
    <div className="border-t border-[var(--line)] pt-4">
      <h3 className="text-sm font-semibold leading-tight text-[var(--ink)]">Citations</h3>
      <ol className="mt-3 grid list-none gap-2 p-0">
        {citations.map((citation, index) => {
          const score = typeof citation.score === 'number' ? citation.score : null;
          return (
            <li
              className="rounded-[var(--radius)] border border-[var(--line)] bg-[var(--surface-2)] p-3"
              key={`${citation.doc_id ?? 'doc'}-${citation.section_id ?? index}`}
            >
              <div className="flex items-start justify-between gap-3">
                {citation.url ? (
                  <a
                    className="themed-link min-w-0 text-sm font-semibold text-[var(--primary)] underline underline-offset-4 transition-colors duration-200 hover:text-[var(--primary-hover)] hover:decoration-[var(--primary-hover)]"
                    href={citation.url}
                    rel="noopener noreferrer"
                    target="_blank"
                  >
                    {citation.citation ?? 'unknown section'}
                  </a>
                ) : (
                  <strong className="min-w-0 text-sm font-semibold text-[var(--ink)]">
                    {citation.citation ?? 'unknown section'}
                  </strong>
                )}
                {score === null ? null : (
                  <span
                    aria-label={`Retrieval score ${score.toFixed(3)}`}
                    className="shrink-0 rounded-[var(--radius)] border border-[var(--line)] bg-[var(--surface)] px-2 py-1 font-mono text-[11px] leading-none text-[var(--muted)]"
                    title="Vector retrieval similarity score"
                  >
                    {score.toFixed(3)}
                  </span>
                )}
              </div>
              {citation.title ? (
                <p className="mt-2 text-[13px] leading-relaxed text-[var(--soft)]">{citation.title}</p>
              ) : null}
              {citation.text ? (
                <pre className="mt-3 max-h-80 overflow-auto rounded-[var(--radius)] border border-[var(--line)] bg-[var(--surface)] p-3 font-mono text-[11px] leading-relaxed text-[var(--soft)]">
                  <code>{citation.text}</code>
                </pre>
              ) : null}
            </li>
          );
        })}
      </ol>
    </div>
  );
}

function getSessionId() {
  if (typeof window === 'undefined') {
    return 'server';
  }
  const existing = window.localStorage.getItem(storageNames.qaSession);
  if (existing) {
    return existing;
  }
  const id = window.crypto.randomUUID();
  window.localStorage.setItem(storageNames.qaSession, id);
  return id;
}

async function askStream(question: string, sessionId: string, handlers: StreamHandlers): Promise<void> {
  const response = await fetch(`${apiBase}/api/qa/stream`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Accept: 'text/event-stream',
      'X-Session-Id': sessionId,
    },
    body: JSON.stringify({ question }),
  });
  if (response.status === 429) {
    throw new Error('rate limit exceeded');
  }
  if (!response.ok) {
    throw new Error(`request failed: ${response.status}`);
  }
  if (!response.body) {
    throw new Error('stream unavailable');
  }

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (value) {
        buffer += decoder.decode(value, { stream: !done });
        const events = buffer.split(/\n\n/);
        buffer = events.pop() ?? '';
        for (const eventText of events) {
          handleStreamEvent(parseSseEvent(eventText), handlers);
        }
      }
      if (done) {
        buffer += decoder.decode();
        if (buffer.trim()) {
          handleStreamEvent(parseSseEvent(buffer), handlers);
        }
        return;
      }
    }
  } finally {
    reader.releaseLock();
  }
}

async function randomQuestion(sessionId: string): Promise<{ question: string }> {
  const response = await fetch(`${apiBase}/api/questions/random`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Session-Id': sessionId,
    },
  });
  if (response.status === 429) {
    throw new Error('rate limit exceeded');
  }
  if (!response.ok) {
    throw new Error(`request failed: ${response.status}`);
  }
  return response.json();
}

function parseSseEvent(eventText: string): { event: string; data: unknown } | null {
  let event = 'message';
  const dataLines: string[] = [];
  for (const line of eventText.split(/\r?\n/)) {
    if (line.startsWith('event:')) {
      event = line.slice(6).trim();
      continue;
    }
    if (line.startsWith('data:')) {
      dataLines.push(line.slice(5).trimStart());
    }
  }
  if (!dataLines.length) {
    return null;
  }
  try {
    return { event, data: JSON.parse(dataLines.join('\n')) };
  } catch (_error) {
    return null;
  }
}

function handleStreamEvent(parsed: { event: string; data: unknown } | null, handlers: StreamHandlers) {
  if (!parsed || !isRecord(parsed.data)) {
    return;
  }
  if (parsed.event === 'metadata') {
    handlers.onMetadata(parsed.data as Partial<QaPayload>);
    return;
  }
  if (parsed.event === 'direct') {
    handlers.onDirect(parsed.data as StreamChunkPayload);
    return;
  }
  if (parsed.event === 'rag') {
    handlers.onRag(parsed.data as StreamChunkPayload);
    return;
  }
  if (parsed.event === 'done') {
    handlers.onDone(parsed.data as unknown as QaPayload);
    return;
  }
  if (parsed.event === 'error') {
    throw new Error('request failed: stream');
  }
}

function appendStreamText(current: string, delta: string) {
  if (!delta) {
    return current;
  }
  if (current === 'Asking DeepSeek V4 Pro directly...' || current === 'Retrieving QUIC context...') {
    return delta;
  }
  return `${current}${delta}`;
}

function emptyStreamMetrics(): StreamMetrics {
  return {
    firstTokenMs: null,
    lastTokenMs: null,
    completionTokens: null,
  };
}

function recordStreamMetrics(
  payload: StreamChunkPayload,
  startedAt: number,
  metricsRef: MutableRefObject<StreamMetrics>,
  setMetrics: Dispatch<SetStateAction<StreamMetrics>>,
) {
  const elapsedMs = Date.now() - startedAt;
  const hasDelta = Boolean(payload.delta);
  const completionTokens = payload.usage?.completion_tokens;
  let next = metricsRef.current;
  let changed = false;

  if (hasDelta) {
    next = { ...next };
    if (next.firstTokenMs === null) {
      next.firstTokenMs = elapsedMs;
    }
    next.lastTokenMs = elapsedMs;
    changed = true;
  }

  if (typeof completionTokens === 'number') {
    if (!changed) {
      next = { ...next };
    }
    next.completionTokens = completionTokens;
    if (next.lastTokenMs === null) {
      next.lastTokenMs = elapsedMs;
    }
    changed = true;
  }

  if (changed) {
    metricsRef.current = next;
    setMetrics(next);
  }
}

function recordStreamUsage(
  usage: Usage | null,
  startedAt: number,
  metricsRef: MutableRefObject<StreamMetrics>,
  setMetrics: Dispatch<SetStateAction<StreamMetrics>>,
) {
  const completionTokens = usage?.completion_tokens;
  if (typeof completionTokens !== 'number') {
    return;
  }

  const elapsedMs = Date.now() - startedAt;
  const next = {
    ...metricsRef.current,
    completionTokens,
    lastTokenMs: metricsRef.current.lastTokenMs ?? elapsedMs,
  };
  metricsRef.current = next;
  setMetrics(next);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

function publicStatus(payload: QaPayload) {
  if (payload.accepted) {
    return 'answered';
  }
  if (payload.reason === 'out_of_scope') {
    return 'question is not related to QUIC';
  }
  if (payload.reason === 'low_retrieval_confidence') {
    return 'not enough context';
  }
  if (payload.reason === 'generation_error' || payload.reason === 'unavailable') {
    return 'temporarily unavailable';
  }
  return 'not answered';
}

function displayModel(model: string) {
  return modelMeta(model).label ?? model.replace(/:free$/, '');
}

function formatElapsed(ms: number) {
  const elapsed = Math.max(0, ms);
  if (elapsed < 1000) {
    return `${Math.round(elapsed)} ms`;
  }
  return `${(elapsed / 1000).toFixed(elapsed < 10_000 ? 1 : 0)} s`;
}

function formatTokens(tokens: number) {
  const safeTokens = Math.max(0, tokens);
  if (safeTokens < 1000) {
    return `${safeTokens} tok`;
  }
  return `${(safeTokens / 1000).toFixed(safeTokens < 10_000 ? 1 : 0)}k tok`;
}

function tokenSpeed(metrics: StreamMetrics, answer: string) {
  if (metrics.firstTokenMs === null || metrics.lastTokenMs === null) {
    return null;
  }

  const exactTokens = metrics.completionTokens;
  const tokens = exactTokens ?? estimateCompletionTokens(answer);
  if (tokens <= 0) {
    return null;
  }

  const streamedMs = Math.max(500, metrics.lastTokenMs - metrics.firstTokenMs);
  return {
    estimated: exactTokens === null,
    tokensPerSecond: tokens / (streamedMs / 1000),
  };
}

function estimateCompletionTokens(answer: string) {
  const text = answer.trim();
  if (!text) {
    return 0;
  }
  return Math.max(1, Math.round(text.length / 4));
}

function formatTokenSpeed(tokensPerSecond: number) {
  const safeRate = Math.max(0, tokensPerSecond);
  if (safeRate < 10) {
    return `${safeRate.toFixed(1)} tok/s`;
  }
  return `${Math.round(safeRate)} tok/s`;
}

function formatUsageTitle(usage: Usage) {
  const parts = [];
  if (typeof usage.prompt_tokens === 'number') {
    parts.push(`prompt ${usage.prompt_tokens}`);
  }
  if (typeof usage.completion_tokens === 'number') {
    parts.push(`completion ${usage.completion_tokens}`);
  }
  if (typeof usage.total_tokens === 'number') {
    parts.push(`total ${usage.total_tokens}`);
  }
  return parts.length ? parts.join(' · ') : 'Token usage';
}

function confidenceLabel(confidence: number) {
  if (confidence >= 0.72) {
    return 'High';
  }
  if (confidence >= 0.45) {
    return 'Med';
  }
  return 'Low';
}

function confidenceClassName(confidence: number) {
  if (confidence >= 0.72) {
    return 'border-[rgba(31,138,101,0.28)] bg-[var(--success-soft)] text-[var(--ok)]';
  }
  if (confidence >= 0.45) {
    return 'border-[rgba(141,109,0,0.28)] bg-[var(--warning-soft)] text-[var(--warning)]';
  }
  return 'border-[rgba(207,45,86,0.28)] bg-[var(--danger-soft)] text-[var(--danger)]';
}

function modelMeta(model: string): ModelMeta {
  if (model === 'deepseek-v4-pro') {
    return {
      provider: 'DeepSeek',
      size: 'V4 Pro',
      avatar: 'DS',
      swatch: '#4f46e5',
      label: 'DeepSeek: V4 Pro',
      iconSrc: '/deepseek-logo-icon.svg',
    };
  }
  return {
    provider: model.split('/', 1).at(0) ?? 'Model',
    size: model.includes(':free') ? 'free' : 'selected',
    avatar: model.slice(0, 2).toUpperCase(),
    swatch: '#6f6f6f',
    label: model.replace(/:free$/, ''),
  };
}

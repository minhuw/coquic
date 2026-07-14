'use client';

import { isValidElement, useEffect, useMemo, useReducer, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import { Check, Copy, RotateCcw, ShieldAlert } from 'lucide-react';
import ReactMarkdown from 'react-markdown';
import type { Components } from 'react-markdown';
import remarkGfm from 'remark-gfm';

import { Button } from '@/components/ui/button';
import { CopyCodeButton } from '@/components/docs/copy-code-button';
import { TableRegion } from '@/components/editorial/table-region';
import { ScrollRegion } from '@/components/ui/scroll-region';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';

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

export type QaPhase =
  | 'ready'
  | 'suggesting'
  | 'streaming'
  | 'completed'
  | 'rejected'
  | 'rate-limited'
  | 'offline'
  | 'failed';

type ChannelPhase = 'waiting' | 'streaming' | 'complete' | 'error';
type ChannelName = 'direct' | 'rag';

interface ChannelState {
  phase: ChannelPhase;
  answer: string;
  usage: Usage | null;
  metrics: StreamMetrics;
  model: string;
}

export interface QaState {
  question: string;
  phase: QaPhase;
  resumePhase: QaPhase;
  statusMessage: string;
  questionError: string;
  suggestionError: string;
  requestMessage: string;
  activeRequestId: number | null;
  activeSuggestId: number | null;
  startedAt: number | null;
  elapsedMs: number | null;
  direct: ChannelState;
  rag: ChannelState;
  ragConfidence: number | null;
  citations: Citation[];
}

export type QaAction =
  | { type: 'question-changed'; question: string }
  | { type: 'question-invalid' }
  | { type: 'suggest-start'; suggestId: number }
  | { type: 'suggest-success'; suggestId: number; question: string }
  | { type: 'suggest-failure'; suggestId: number; phase: Exclude<QaPhase, 'suggesting'>; message: string; status: string }
  | { type: 'submit-start'; requestId: number; startedAt: number }
  | { type: 'tick'; requestId: number; elapsedMs: number }
  | { type: 'metadata'; requestId: number; payload: Partial<QaPayload> }
  | { type: 'channel'; requestId: number; channel: ChannelName; payload: StreamChunkPayload; elapsedMs: number }
  | { type: 'done'; requestId: number; payload: QaPayload; elapsedMs: number }
  | { type: 'request-failure'; requestId: number; phase: 'rate-limited' | 'offline' | 'failed'; message: string; elapsedMs: number };

const apiBase = '/rag-api';
const qaModel = 'deepseek-v4-pro';
const maxQuestionLength = 1200;
const storageNames = {
  qaSession: 'coquic-qa-session',
} as const;

function emptyStreamMetrics(): StreamMetrics {
  return {
    firstTokenMs: null,
    lastTokenMs: null,
    completionTokens: null,
  };
}

function emptyChannel(): ChannelState {
  return {
    phase: 'waiting',
    answer: '',
    usage: null,
    metrics: emptyStreamMetrics(),
    model: qaModel,
  };
}

export function createInitialQaState(): QaState {
  return {
    question: '',
    phase: 'ready',
    resumePhase: 'ready',
    statusMessage: 'Ready for a QUIC specification question.',
    questionError: '',
    suggestionError: '',
    requestMessage: '',
    activeRequestId: null,
    activeSuggestId: null,
    startedAt: null,
    elapsedMs: null,
    direct: emptyChannel(),
    rag: emptyChannel(),
    ragConfidence: null,
    citations: [],
  };
}

export function qaReducer(state: QaState, action: QaAction): QaState {
  switch (action.type) {
    case 'question-changed':
      return { ...state, question: action.question, questionError: '', suggestionError: '' };
    case 'question-invalid':
      return {
        ...state,
        questionError: 'Enter a QUIC specification question before asking.',
        statusMessage: 'A question is required.',
      };
    case 'suggest-start':
      return {
        ...state,
        phase: 'suggesting',
        resumePhase: resumablePhase(state),
        statusMessage: 'Suggesting a QUIC specification question.',
        questionError: '',
        suggestionError: '',
        requestMessage: '',
        activeSuggestId: action.suggestId,
      };
    case 'suggest-success':
      if (state.activeSuggestId !== action.suggestId) return state;
      return {
        ...state,
        question: action.question,
        phase: state.resumePhase,
        statusMessage: 'Suggested question ready.',
        questionError: '',
        suggestionError: '',
        activeSuggestId: null,
      };
    case 'suggest-failure':
      if (state.activeSuggestId !== action.suggestId) return state;
      return {
        ...state,
        phase: action.phase,
        statusMessage: action.status,
        questionError: '',
        suggestionError: action.message,
        activeSuggestId: null,
      };
    case 'submit-start': {
      const channel = emptyChannel();
      return {
        ...state,
        phase: 'streaming',
        resumePhase: 'ready',
        statusMessage: 'Receiving direct and RAG answers.',
        questionError: '',
        suggestionError: '',
        requestMessage: '',
        activeRequestId: action.requestId,
        activeSuggestId: null,
        startedAt: action.startedAt,
        elapsedMs: 0,
        direct: channel,
        rag: emptyChannel(),
        ragConfidence: null,
        citations: [],
      };
    }
    case 'tick':
      if (state.activeRequestId !== action.requestId) return state;
      return { ...state, elapsedMs: action.elapsedMs };
    case 'metadata':
      if (state.activeRequestId !== action.requestId) return state;
      return {
        ...state,
        citations: action.payload.citations ?? [],
        ragConfidence: typeof action.payload.rag_confidence === 'number' ? action.payload.rag_confidence : null,
      };
    case 'channel':
      if (state.activeRequestId !== action.requestId) return state;
      return {
        ...state,
        [action.channel]: updateChannel(state[action.channel], action.payload, action.elapsedMs),
      };
    case 'done':
      if (state.activeRequestId !== action.requestId) return state;
      return completeRequest(state, action.payload, action.elapsedMs);
    case 'request-failure':
      if (state.activeRequestId !== action.requestId) return state;
      return {
        ...state,
        phase: action.phase,
        statusMessage: action.message,
        requestMessage: action.message,
        activeRequestId: null,
        startedAt: null,
        elapsedMs: action.elapsedMs,
        direct: failIncompleteChannel(state.direct),
        rag: failIncompleteChannel(state.rag),
      };
    default:
      return state;
  }
}

function resumablePhase(state: QaState): QaPhase {
  if (state.phase === 'completed' || state.phase === 'rejected') return state.phase;
  if (state.direct.answer || state.rag.answer) return state.resumePhase;
  return 'ready';
}

function updateChannel(channel: ChannelState, payload: StreamChunkPayload, elapsedMs: number): ChannelState {
  const answer = payload.delta ? `${channel.answer}${payload.delta}` : channel.answer;
  const completionTokens = payload.usage?.completion_tokens;
  const hasDelta = Boolean(payload.delta);
  const metrics = { ...channel.metrics };

  if (hasDelta) {
    metrics.firstTokenMs ??= elapsedMs;
    metrics.lastTokenMs = elapsedMs;
  }
  if (typeof completionTokens === 'number') {
    metrics.completionTokens = completionTokens;
    metrics.lastTokenMs ??= elapsedMs;
  }

  return {
    phase: payload.done ? 'complete' : hasDelta || channel.phase === 'streaming' ? 'streaming' : channel.phase,
    answer,
    usage: payload.usage ?? channel.usage,
    metrics,
    model: payload.model ?? channel.model,
  };
}

function completeRequest(state: QaState, payload: QaPayload, elapsedMs: number): QaState {
  const directUsage = payload.direct_usage ?? null;
  const ragUsage = payload.rag_usage ?? payload.usage ?? null;
  return {
    ...state,
    phase: payload.accepted ? 'completed' : 'rejected',
    resumePhase: payload.accepted ? 'completed' : 'rejected',
    statusMessage: publicStatus(payload),
    requestMessage: payload.accepted ? '' : rejectionMessage(payload.reason),
    activeRequestId: null,
    startedAt: null,
    elapsedMs,
    direct: completeChannel(
      state.direct,
      payload.direct_answer ?? payload.answer ?? 'No direct answer returned.',
      directUsage,
      payload.direct_model ?? qaModel,
      elapsedMs,
    ),
    rag: completeChannel(
      state.rag,
      payload.rag_answer ?? payload.answer ?? 'No RAG answer returned.',
      ragUsage,
      payload.rag_model ?? qaModel,
      elapsedMs,
    ),
    ragConfidence: typeof payload.rag_confidence === 'number' ? payload.rag_confidence : null,
    citations: payload.citations ?? [],
  };
}

function completeChannel(
  channel: ChannelState,
  answer: string,
  usage: Usage | null,
  model: string,
  elapsedMs: number,
): ChannelState {
  const completionTokens = usage?.completion_tokens;
  return {
    phase: 'complete',
    answer,
    usage,
    model,
    metrics: {
      ...channel.metrics,
      completionTokens: typeof completionTokens === 'number' ? completionTokens : channel.metrics.completionTokens,
      lastTokenMs:
        typeof completionTokens === 'number' ? (channel.metrics.lastTokenMs ?? elapsedMs) : channel.metrics.lastTokenMs,
    },
  };
}

function failIncompleteChannel(channel: ChannelState): ChannelState {
  if (channel.phase === 'complete') return channel;
  return { ...channel, phase: 'error' };
}

export function QaClient() {
  const [state, dispatch] = useReducer(qaReducer, undefined, createInitialQaState);
  const formRef = useRef<HTMLFormElement>(null);
  const requestSequence = useRef(0);
  const suggestSequence = useRef(0);
  const streamController = useRef<AbortController | null>(null);
  const suggestController = useRef<AbortController | null>(null);
  const sessionId = useMemo(() => getSessionId(), []);
  const busy = state.phase === 'streaming';
  const suggesting = state.phase === 'suggesting';
  const hasResults = Boolean(state.direct.answer || state.rag.answer);
  const showComparison = busy || hasResults || state.phase === 'completed' || state.phase === 'rejected';

  useEffect(() => {
    return () => {
      requestSequence.current += 1;
      suggestSequence.current += 1;
      streamController.current?.abort();
      suggestController.current?.abort();
    };
  }, []);

  useEffect(() => {
    if (!busy || state.startedAt === null || state.activeRequestId === null) return;
    const requestId = state.activeRequestId;
    const updateElapsed = () => {
      dispatch({ type: 'tick', requestId, elapsedMs: Date.now() - state.startedAt! });
    };
    updateElapsed();
    const intervalId = window.setInterval(updateElapsed, 250);
    return () => {
      window.clearInterval(intervalId);
    };
  }, [busy, state.activeRequestId, state.startedAt]);

  async function submit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const trimmed = state.question.trim();
    if (!trimmed) {
      dispatch({ type: 'question-invalid' });
      return;
    }

    streamController.current?.abort();
    suggestController.current?.abort();
    const controller = new AbortController();
    streamController.current = controller;
    const requestId = requestSequence.current + 1;
    requestSequence.current = requestId;
    const startedAt = Date.now();
    let receivedDone = false;
    dispatch({ type: 'submit-start', requestId, startedAt });

    try {
      await askStream(
        trimmed,
        sessionId,
        {
          onMetadata: (payload) => {
            dispatch({ type: 'metadata', requestId, payload });
          },
          onDirect: (payload) => {
            dispatch({ type: 'channel', requestId, channel: 'direct', payload, elapsedMs: Date.now() - startedAt });
          },
          onRag: (payload) => {
            dispatch({ type: 'channel', requestId, channel: 'rag', payload, elapsedMs: Date.now() - startedAt });
          },
          onDone: (payload) => {
            receivedDone = true;
            dispatch({ type: 'done', requestId, payload, elapsedMs: Date.now() - startedAt });
          },
        },
        controller.signal,
      );
      if (!receivedDone && !controller.signal.aborted && requestId === requestSequence.current) {
        dispatch({
          type: 'request-failure',
          requestId,
          phase: 'failed',
          message: 'The specification QA request could not be completed. Try again.',
          elapsedMs: Date.now() - startedAt,
        });
      }
    } catch (error) {
      if (controller.signal.aborted || requestId !== requestSequence.current) return;
      const failure = requestFailure(error);
      dispatch({
        type: 'request-failure',
        requestId,
        phase: failure.phase,
        message: failure.message,
        elapsedMs: Date.now() - startedAt,
      });
    } finally {
      if (streamController.current === controller) streamController.current = null;
    }
  }

  async function suggestQuestion() {
    suggestController.current?.abort();
    const controller = new AbortController();
    suggestController.current = controller;
    const suggestId = suggestSequence.current + 1;
    suggestSequence.current = suggestId;
    dispatch({ type: 'suggest-start', suggestId });

    try {
      const payload = await randomQuestion(sessionId, controller.signal);
      dispatch({ type: 'suggest-success', suggestId, question: payload.question });
    } catch (error) {
      if (controller.signal.aborted || suggestId !== suggestSequence.current) return;
      const rateLimited = error instanceof Error && error.message === 'rate limit exceeded';
      const offline = isOfflineError(error);
      dispatch({
        type: 'suggest-failure',
        suggestId,
        phase: rateLimited ? 'rate-limited' : offline ? 'offline' : 'failed',
        message: rateLimited
          ? 'Random question limit reached. Try again in a minute.'
          : 'Random question generation is temporarily unavailable.',
        status: rateLimited ? 'rate limit exceeded' : 'request failed',
      });
    } finally {
      if (suggestController.current === controller) suggestController.current = null;
    }
  }

  return (
    <section className="qa-workspace" aria-label="Ask QUIC specification questions" data-qa-phase={state.phase}>
      <div className="qa-question-panel">
        <form className="qa-form" ref={formRef} onSubmit={(event) => void submit(event)}>
          <div className="qa-field-heading">
            <label className="qa-label" htmlFor="qa-question">
              Question
            </label>
            <span className="qa-character-count" id="qa-question-count">
              {state.question.length.toLocaleString()} / {maxQuestionLength.toLocaleString()}
            </span>
          </div>
          <textarea
            aria-describedby="qa-question-help qa-question-count"
            aria-errormessage={state.questionError ? 'qa-question-error' : undefined}
            aria-invalid={Boolean(state.questionError)}
            className="qa-question"
            id="qa-question"
            name="question"
            maxLength={maxQuestionLength}
            rows={5}
            required
            value={state.question}
            onChange={(event) => {
              dispatch({ type: 'question-changed', question: event.target.value });
            }}
            onKeyDown={(event) => {
              if (event.key === 'Enter' && event.ctrlKey) {
                event.preventDefault();
                event.currentTarget.form?.requestSubmit();
              }
            }}
            placeholder="How does QUIC ACK delay affect loss recovery?"
          />
          <div className="qa-form-footer">
            <div className="qa-provider">
              <img className="qa-provider-logo" src="/deepseek-logo-icon.svg" alt="" aria-hidden="true" />
              <span>DeepSeek V4 Pro</span>
              <PrivacyNotice />
            </div>
            <div className="qa-actions">
              <Button
                className="qa-suggest-button"
                type="button"
                variant="outline"
                disabled={busy || suggesting}
                loading={suggesting}
                loadingLabel="Suggesting question"
                onClick={() => void suggestQuestion()}
              >
                Suggest question
              </Button>
              <Button
                className="qa-ask-button"
                type="submit"
                disabled={busy || suggesting || !state.question.trim()}
                loading={busy}
                loadingLabel="Asking question"
              >
                Ask
              </Button>
            </div>
          </div>
          <p className="qa-form-help" id="qa-question-help">
            Questions and answers are not stored by CoQUIC.
          </p>
          <p className="qa-live-status sr-only" role="status" aria-live="polite">
            {state.statusMessage}
          </p>
          {state.questionError ? (
            <p className="qa-field-error" id="qa-question-error" role="alert">
              {state.questionError}
            </p>
          ) : null}
          {state.suggestionError ? (
            <p className="qa-field-error" role="alert">
              {state.suggestionError}
            </p>
          ) : null}
        </form>
      </div>

      {state.requestMessage ? (
        <RequestStatus
          message={state.requestMessage}
          phase={state.phase}
          onRetry={() => formRef.current?.requestSubmit()}
        />
      ) : null}

      {showComparison ? (
        <section className="qa-results" aria-label="Answer comparison">
          <div className="qa-results-desktop">
            <AnswerPanel channel={state.direct} elapsedMs={state.elapsedMs} kind="direct" />
            <AnswerPanel
              channel={state.rag}
              citationHeadingId="qa-desktop-citations"
              citations={state.citations}
              confidence={state.ragConfidence}
              elapsedMs={state.elapsedMs}
              kind="rag"
            />
          </div>
          <Tabs className="qa-results-mobile" defaultValue="direct">
            <TabsList aria-label="Answer comparison">
              <TabsTrigger value="direct">
                Direct
                <ChannelTabStatus phase={state.direct.phase} />
              </TabsTrigger>
              <TabsTrigger value="rag">
                With RAG
                <ChannelTabStatus phase={state.rag.phase} />
              </TabsTrigger>
            </TabsList>
            <TabsContent value="direct">
              <AnswerPanel channel={state.direct} elapsedMs={state.elapsedMs} kind="direct" />
            </TabsContent>
            <TabsContent value="rag">
              <AnswerPanel
                channel={state.rag}
                citationHeadingId="qa-mobile-citations"
                citations={state.citations}
                confidence={state.ragConfidence}
                elapsedMs={state.elapsedMs}
                kind="rag"
              />
            </TabsContent>
          </Tabs>
        </section>
      ) : null}
    </section>
  );
}

function PrivacyNotice() {
  const [open, setOpen] = useState(false);
  return (
    <span className="qa-privacy" data-open={open || undefined}>
      <button
        aria-describedby="qa-privacy-content"
        aria-expanded={open}
        aria-label="Privacy notice"
        className="qa-icon-button qa-privacy-trigger"
        onClick={() => setOpen((current) => !current)}
        onKeyDown={(event) => {
          if (event.key === 'Escape') setOpen(false);
        }}
        type="button"
      >
        <ShieldAlert aria-hidden="true" />
      </button>
      <span className="qa-privacy-content" id="qa-privacy-content" role="tooltip">
        CoQUIC does not store your questions or generated answers. DeepSeek V4 Pro processes QA requests; refer to
        DeepSeek&apos;s privacy policy for how DeepSeek handles submitted data.
      </span>
    </span>
  );
}

function RequestStatus({ message, phase, onRetry }: { message: string; phase: QaPhase; onRetry(): void }) {
  return (
    <div className="qa-request-status" data-status={statusTone(phase)} role={phase === 'failed' ? 'alert' : 'status'}>
      <div>
        <strong>{statusTitle(phase)}</strong>
        <p>{message}</p>
      </div>
      <Button className="qa-retry-button" type="button" variant="outline" onClick={onRetry}>
        <RotateCcw aria-hidden="true" />
        Retry
      </Button>
    </div>
  );
}

function ChannelTabStatus({ phase }: { phase: ChannelPhase }) {
  if (phase !== 'waiting' && phase !== 'streaming') return null;
  return <span className="qa-tab-status sr-only">, {phase === 'waiting' ? 'waiting' : 'streaming'}</span>;
}

function AnswerPanel({
  channel,
  citationHeadingId,
  citations = [],
  confidence,
  elapsedMs,
  kind,
}: {
  channel: ChannelState;
  citationHeadingId?: string;
  citations?: Citation[];
  confidence?: number | null;
  elapsedMs: number | null;
  kind: ChannelName;
}) {
  const title = kind === 'direct' ? 'Direct' : 'With RAG';
  const busy = channel.phase === 'waiting' || channel.phase === 'streaming';
  return (
    <article className="qa-answer" aria-busy={busy} data-channel={kind} data-channel-phase={channel.phase}>
      <header className="qa-answer-header">
        <div className="qa-answer-title-row">
          <div>
            <p className="qa-answer-kicker">{kind === 'direct' ? 'Model baseline' : 'Specification-grounded'}</p>
            <h2>{title}</h2>
          </div>
          <CopyAnswerButton answer={channel.answer} disabled={busy} label={`${title} answer`} />
        </div>
        <AnswerMetadata
          answer={channel.answer}
          confidence={kind === 'rag' ? (confidence ?? null) : null}
          elapsedMs={elapsedMs}
          metrics={channel.metrics}
          model={channel.model}
          usage={channel.usage}
        />
      </header>
      <div className="qa-answer-body">
        {channel.answer ? (
          <MarkdownAnswer>{channel.answer}</MarkdownAnswer>
        ) : busy ? (
          <div className="qa-answer-placeholder" aria-hidden="true">
            <span />
            <span />
            <span />
          </div>
        ) : (
          <p className="qa-answer-empty">No answer text was returned.</p>
        )}
        {kind === 'rag' && citations.length > 0 ? (
          <Citations citations={citations} headingId={citationHeadingId ?? 'qa-citations'} />
        ) : null}
      </div>
    </article>
  );
}

function AnswerMetadata({
  answer,
  confidence,
  elapsedMs,
  metrics,
  model,
  usage,
}: {
  answer: string;
  confidence: number | null;
  elapsedMs: number | null;
  metrics: StreamMetrics;
  model: string;
  usage: Usage | null;
}) {
  const speed = tokenSpeed(metrics, answer);
  const speedLabel = speed
    ? `${speed.estimated ? 'Approximately ' : ''}${formatTokenSpeed(speed.tokensPerSecond)}`
    : 'Pending';
  const usageLabel = typeof usage?.total_tokens === 'number' ? formatTokens(usage.total_tokens) : 'Pending';
  const confidenceValue = confidence === null ? null : Math.max(0, Math.min(1, confidence));

  return (
    <dl className="qa-metadata">
      <MetadataRow label="Model" value={displayModel(model)} />
      <MetadataRow label="First token" value={metrics.firstTokenMs === null ? 'Pending' : formatElapsed(metrics.firstTokenMs)} />
      <MetadataRow label="Generation speed" value={speedLabel} />
      <MetadataRow label="Elapsed" value={elapsedMs === null ? 'Pending' : formatElapsed(elapsedMs)} />
      <MetadataRow label="Token usage" title={usage ? formatUsageTitle(usage) : undefined} value={usageLabel} />
      {confidenceValue === null ? null : (
        <MetadataRow
          label="RAG confidence"
          title="RAG confidence is based on retrieved section similarity scores after low-score results are filtered."
          value={`${Math.round(confidenceValue * 100)}% (${confidenceLabel(confidenceValue)})`}
        />
      )}
    </dl>
  );
}

function MetadataRow({ label, title, value }: { label: string; title?: string; value: string }) {
  return (
    <div className="qa-metadata-row" title={title}>
      <dt>{label}</dt>
      <dd>{value}</dd>
    </div>
  );
}

function CopyAnswerButton({ answer, disabled, label }: { answer: string; disabled: boolean; label: string }) {
  const [copyState, setCopyState] = useState<'ready' | 'copied' | 'failed'>('ready');
  const resetTimer = useRef<number | null>(null);
  const copyDisabled = disabled || !answer.trim();

  useEffect(() => {
    return () => {
      if (resetTimer.current !== null) window.clearTimeout(resetTimer.current);
    };
  }, []);

  async function copyAnswer() {
    if (copyDisabled) return;
    try {
      await window.navigator.clipboard.writeText(answer);
      setCopyState('copied');
    } catch (_error) {
      setCopyState('failed');
    }
    if (resetTimer.current !== null) window.clearTimeout(resetTimer.current);
    resetTimer.current = window.setTimeout(() => setCopyState('ready'), 1600);
  }

  const accessibleLabel =
    copyState === 'copied' ? `${label} copied` : copyState === 'failed' ? `Unable to copy ${label}` : `Copy ${label}`;
  return (
    <span className="qa-copy-control">
      <button
        aria-label={accessibleLabel}
        className="qa-icon-button qa-copy-button"
        disabled={copyDisabled}
        onClick={() => void copyAnswer()}
        title={accessibleLabel}
        type="button"
      >
        {copyState === 'copied' ? <Check aria-hidden="true" /> : <Copy aria-hidden="true" />}
      </button>
      <span className="sr-only" role="status" aria-live="polite">
        {copyState === 'copied'
          ? `${label} copied to clipboard.`
          : copyState === 'failed'
            ? `Unable to copy ${label}. Try again.`
            : ''}
      </span>
    </span>
  );
}

function MarkdownAnswer({ children }: { children: string }) {
  return (
    <div className="article-content qa-markdown">
      <ReactMarkdown components={markdownComponents} remarkPlugins={[remarkGfm]}>{children}</ReactMarkdown>
    </div>
  );
}

const markdownComponents: Components = {
  pre: MarkdownCodeBlock,
  table: MarkdownTable,
};

function MarkdownTable({ children }: { children?: ReactNode }) {
  return (
    <TableRegion label="Answer data table">
      <table>{children}</table>
    </TableRegion>
  );
}

function MarkdownCodeBlock({ children }: { children?: ReactNode }) {
  const codeElement = isValidElement<{ children?: ReactNode; className?: string }>(children) ? children : null;
  const language = codeElement?.props.className?.match(/language-([^\s]+)/)?.at(1) ?? 'text';
  const code = String(codeElement?.props.children ?? '').replace(/\n$/, '');
  return (
    <div className="editorial-code-block" data-editorial-code-block="true">
      <div className="editorial-code-toolbar">
        <span className="editorial-code-language">{language}</span>
        <CopyCodeButton code={code} />
      </div>
      <ScrollRegion aria-label={`${language} answer code`} axis="horizontal" className="editorial-code-scroll">
        <pre>
          <code data-language={language}>{code}</code>
        </pre>
      </ScrollRegion>
    </div>
  );
}

function Citations({ citations, headingId }: { citations: Citation[]; headingId: string }) {
  return (
    <section className="qa-citations" aria-labelledby={headingId}>
      <div className="qa-citations-heading">
        <h3 id={headingId}>Supporting evidence</h3>
        <span>{citations.length} {citations.length === 1 ? 'source' : 'sources'}</span>
      </div>
      <ol>
        {citations.map((citation, index) => {
          const score = typeof citation.score === 'number' ? citation.score : null;
          const source = citation.citation ?? 'unknown section';
          return (
            <li className="qa-citation" key={`${citation.doc_id ?? 'doc'}-${citation.section_id ?? index}`}>
              <div className="qa-citation-main">
                <div className="qa-citation-labels">
                  {citation.url ? (
                    <a href={citation.url} rel="noopener noreferrer" target="_blank">
                      {source}
                    </a>
                  ) : (
                    <strong>{source}</strong>
                  )}
                  {citation.title ? <p>{citation.title}</p> : null}
                </div>
                {score === null ? null : (
                  <span
                    aria-label={`Retrieval similarity ${score.toFixed(3)}`}
                    className="qa-retrieval-score"
                    title="Vector retrieval similarity score"
                  >
                    Similarity {score.toFixed(3)}
                  </span>
                )}
              </div>
              {citation.text ? (
                <details className="qa-citation-disclosure">
                  <summary>RFC excerpt</summary>
                  <pre
                    aria-label={`${source} excerpt`}
                    className="qa-citation-excerpt"
                    data-scroll-region="true"
                    role="region"
                    tabIndex={0}
                  >
                    <code>{citation.text}</code>
                  </pre>
                </details>
              ) : null}
            </li>
          );
        })}
      </ol>
    </section>
  );
}

async function askStream(
  question: string,
  sessionId: string,
  handlers: StreamHandlers,
  signal?: AbortSignal,
): Promise<void> {
  const response = await fetch(`${apiBase}/api/qa/stream`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Accept: 'text/event-stream',
      'X-Session-Id': sessionId,
    },
    body: JSON.stringify({ question }),
    signal,
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

async function randomQuestion(sessionId: string, signal?: AbortSignal): Promise<{ question: string }> {
  const response = await fetch(`${apiBase}/api/questions/random`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Session-Id': sessionId,
    },
    signal,
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
  if (!dataLines.length) return null;
  try {
    return { event, data: JSON.parse(dataLines.join('\n')) };
  } catch (_error) {
    return null;
  }
}

function handleStreamEvent(parsed: { event: string; data: unknown } | null, handlers: StreamHandlers) {
  if (!parsed || !isRecord(parsed.data)) return;
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
  if (parsed.event === 'error') throw new Error('request failed: stream');
}

function getSessionId() {
  if (typeof window === 'undefined') return 'server';
  const existing = window.localStorage.getItem(storageNames.qaSession);
  if (existing) return existing;
  const id = window.crypto.randomUUID();
  window.localStorage.setItem(storageNames.qaSession, id);
  return id;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

function publicStatus(payload: QaPayload) {
  if (payload.accepted) return 'answered';
  if (payload.reason === 'out_of_scope') return 'question is not related to QUIC';
  if (payload.reason === 'low_retrieval_confidence') return 'not enough context';
  if (payload.reason === 'generation_error' || payload.reason === 'unavailable') return 'temporarily unavailable';
  return 'not answered';
}

function rejectionMessage(reason: string) {
  if (reason === 'out_of_scope') return 'This question is outside the QUIC specification scope.';
  if (reason === 'low_retrieval_confidence') {
    return 'The retrieved specification evidence was not strong enough to answer this question.';
  }
  if (reason === 'generation_error' || reason === 'unavailable') {
    return 'Answer generation is temporarily unavailable.';
  }
  return 'The question could not be answered.';
}

function requestFailure(error: unknown): { phase: 'rate-limited' | 'offline' | 'failed'; message: string } {
  if (error instanceof Error && error.message === 'rate limit exceeded') {
    return { phase: 'rate-limited', message: 'Request limit reached. Try again in a minute.' };
  }
  if (isOfflineError(error)) {
    return { phase: 'offline', message: 'Unable to reach specification QA. Check your connection and try again.' };
  }
  return { phase: 'failed', message: 'The specification QA request could not be completed. Try again.' };
}

function isOfflineError(error: unknown) {
  if (error instanceof TypeError) return true;
  return error instanceof Error && /offline|network|failed to fetch/i.test(error.message);
}

function statusTitle(phase: QaPhase) {
  if (phase === 'rejected') return 'No supported answer';
  if (phase === 'rate-limited') return 'Request limit reached';
  if (phase === 'offline') return 'QA service offline';
  return 'Request failed';
}

function statusTone(phase: QaPhase) {
  if (phase === 'rejected' || phase === 'rate-limited') return 'warning';
  return 'danger';
}

function displayModel(model: string) {
  return model === qaModel ? 'DeepSeek: V4 Pro' : model.replace(/:free$/, '');
}

function formatElapsed(ms: number) {
  const elapsed = Math.max(0, ms);
  if (elapsed < 1000) return `${Math.round(elapsed)} ms`;
  return `${(elapsed / 1000).toFixed(elapsed < 10_000 ? 1 : 0)} s`;
}

function formatTokens(tokens: number) {
  const safeTokens = Math.max(0, tokens);
  if (safeTokens < 1000) return `${safeTokens} tok`;
  return `${(safeTokens / 1000).toFixed(safeTokens < 10_000 ? 1 : 0)}k tok`;
}

function tokenSpeed(metrics: StreamMetrics, answer: string) {
  if (metrics.firstTokenMs === null || metrics.lastTokenMs === null) return null;
  const exactTokens = metrics.completionTokens;
  const tokens = exactTokens ?? estimateCompletionTokens(answer);
  if (tokens <= 0) return null;
  const streamedMs = Math.max(500, metrics.lastTokenMs - metrics.firstTokenMs);
  return {
    estimated: exactTokens === null,
    tokensPerSecond: tokens / (streamedMs / 1000),
  };
}

function estimateCompletionTokens(answer: string) {
  const text = answer.trim();
  if (!text) return 0;
  return Math.max(1, Math.round(text.length / 4));
}

function formatTokenSpeed(tokensPerSecond: number) {
  const safeRate = Math.max(0, tokensPerSecond);
  if (safeRate < 10) return `${safeRate.toFixed(1)} tok/s`;
  return `${Math.round(safeRate)} tok/s`;
}

function formatUsageTitle(usage: Usage) {
  const parts = [];
  if (typeof usage.prompt_tokens === 'number') parts.push(`prompt ${usage.prompt_tokens}`);
  if (typeof usage.completion_tokens === 'number') parts.push(`completion ${usage.completion_tokens}`);
  if (typeof usage.total_tokens === 'number') parts.push(`total ${usage.total_tokens}`);
  return parts.length ? parts.join(' / ') : 'Token usage';
}

function confidenceLabel(confidence: number) {
  if (confidence >= 0.72) return 'High';
  if (confidence >= 0.45) return 'Medium';
  return 'Low';
}

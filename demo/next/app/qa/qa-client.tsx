'use client';

import { useEffect, useMemo, useRef, useState } from 'react';
import { Check, ChevronDown } from 'lucide-react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';

import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';

type Usage = {
  prompt_tokens?: number | null;
  completion_tokens?: number | null;
  total_tokens?: number | null;
};

type Citation = {
  citation?: string | null;
  doc_id?: string | null;
  section_id?: string | null;
  title?: string | null;
  score?: number | null;
  text?: string | null;
  url?: string | null;
};

type QaPayload = {
  answer: string;
  accepted: boolean;
  reason: string;
  citations?: Citation[];
  usage?: Usage | null;
  direct_answer?: string | null;
  direct_usage?: Usage | null;
  direct_model?: string | null;
  rag_answer?: string | null;
  rag_usage?: Usage | null;
  rag_model?: string | null;
};

type ModelOption = {
  id: string;
  label: string;
};

type ModelMeta = {
  provider: string;
  size: string;
  avatar: string;
  swatch: string;
  label?: string;
  iconSrc?: string;
};

type HealthPayload = {
  answer_models?: ModelOption[];
};

const fallbackModelOptions: ModelOption[] = [
  { id: 'openai/gpt-oss-120b:free', label: 'OpenAI: gpt-oss-120b (free)' },
  { id: 'nvidia/nemotron-3-super-120b-a12b:free', label: 'NVIDIA: Nemotron 3 Super (free)' },
  { id: 'moonshotai/kimi-k2.6:free', label: 'MoonshotAI: Kimi K2.6 (free)' },
  { id: 'qwen/qwen3-coder:free', label: 'Qwen: Qwen3 Coder 480B A35B (free)' },
  { id: 'meta-llama/llama-3.3-70b-instruct:free', label: 'Meta: Llama 3.3 70B Instruct (free)' },
];

const apiBase = '/rag-api';
const sessionKey = 'coquic-qa-session';

export function QaClient() {
  const [question, setQuestion] = useState('');
  const [status, setStatus] = useState('ready');
  const [busy, setBusy] = useState(false);
  const [suggesting, setSuggesting] = useState(false);
  const [directAnswer, setDirectAnswer] = useState('');
  const [ragAnswer, setRagAnswer] = useState('');
  const [directModel, setDirectModel] = useState('');
  const [ragModel, setRagModel] = useState('');
  const [queryStartedAt, setQueryStartedAt] = useState<number | null>(null);
  const [queryElapsedMs, setQueryElapsedMs] = useState<number | null>(null);
  const [citations, setCitations] = useState<Citation[]>([]);
  const [questionError, setQuestionError] = useState('');
  const [selectedModel, setSelectedModel] = useState(fallbackModelOptions[0].id);
  const [modelOptions, setModelOptions] = useState<ModelOption[]>(fallbackModelOptions);
  const [modelMenuOpen, setModelMenuOpen] = useState(false);
  const suggestRequestId = useRef(0);

  const hasResults = directAnswer.length > 0 || ragAnswer.length > 0;
  const hasCitations = citations.length > 0;
  const sessionId = useMemo(() => getSessionId(), []);

  useEffect(() => {
    void loadHealth().then((payload) => {
      if (payload?.answer_models?.length) {
        setModelOptions(payload.answer_models);
        setSelectedModel((current) => {
          const options = payload.answer_models ?? [];
          return options.some((option) => option.id === current) ? current : options[0].id;
        });
      }
    });
  }, []);

  useEffect(() => {
    if (!busy || queryStartedAt === null) {
      return;
    }

    const updateElapsed = () => setQueryElapsedMs(Date.now() - queryStartedAt);
    updateElapsed();
    const intervalId = window.setInterval(updateElapsed, 250);
    return () => window.clearInterval(intervalId);
  }, [busy, queryStartedAt]);

  useEffect(() => {
    if (!modelMenuOpen) {
      return;
    }

    function closeOnOutside(event: PointerEvent) {
      const target = event.target;
      if (target instanceof Element && !target.closest('[data-model-picker]')) {
        setModelMenuOpen(false);
      }
    }

    function closeOnEscape(event: KeyboardEvent) {
      if (event.key === 'Escape') {
        setModelMenuOpen(false);
      }
    }

    document.addEventListener('pointerdown', closeOnOutside);
    document.addEventListener('keydown', closeOnEscape);
    return () => {
      document.removeEventListener('pointerdown', closeOnOutside);
      document.removeEventListener('keydown', closeOnEscape);
    };
  }, [modelMenuOpen]);

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
    setDirectAnswer('Asking the selected free model directly...');
    setRagAnswer('Retrieving QUIC context...');
    setDirectModel(selectedModel);
    setRagModel(selectedModel);
    setCitations([]);

    try {
      const payload = await ask(trimmed, sessionId, selectedModel);
      setDirectAnswer(payload.direct_answer || payload.answer || 'No direct answer returned.');
      setRagAnswer(payload.rag_answer || payload.answer || 'No RAG answer returned.');
      setDirectModel(payload.direct_model || selectedModel);
      setRagModel(payload.rag_model || selectedModel);
      setCitations(payload.citations || []);
      setStatus(publicStatus(payload));
    } catch (error) {
      const message = error instanceof Error ? error.message : 'request failed';
      setDirectAnswer(message);
      setRagAnswer(message);
      setDirectModel(selectedModel);
      setRagModel(selectedModel);
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
          <form className="grid gap-3" onSubmit={submit}>
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
              onChange={(event) => setQuestion(event.target.value)}
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
                <ModelPicker
                  disabled={busy || suggesting}
                  onChange={setSelectedModel}
                  onOpenChange={setModelMenuOpen}
                  open={modelMenuOpen}
                  options={modelOptions}
                  value={selectedModel}
                />
                <span className="inline-flex h-9 shrink-0 items-center gap-1.5 text-xs font-medium text-[var(--muted)]">
                  <span>Powered by OpenRouter</span>
                  <img className="size-[18px]" src="/openrouter-favicon.ico" alt="" aria-hidden="true" />
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
        <div className="grid gap-3 lg:grid-cols-2">
          <Card className="min-h-[280px]">
            <CardHeader className="flex flex-row items-center justify-between gap-3">
              <CardTitle>Direct</CardTitle>
              <span className="flex min-w-0 max-w-[72%] items-center justify-end gap-2">
                <ElapsedBadge elapsedMs={queryElapsedMs} />
                <ModelBadge model={directModel || selectedModel} />
              </span>
            </CardHeader>
            <CardContent>
              <MarkdownAnswer>{directAnswer}</MarkdownAnswer>
            </CardContent>
          </Card>

          <Card className="min-h-[280px]">
            <CardHeader className="flex flex-row items-center justify-between gap-3">
              <CardTitle>With RAG</CardTitle>
              <span className="flex min-w-0 max-w-[72%] items-center justify-end gap-2">
                <ElapsedBadge elapsedMs={queryElapsedMs} />
                <ModelBadge model={ragModel || selectedModel} />
              </span>
            </CardHeader>
            <CardContent className="grid gap-4">
              <MarkdownAnswer>{ragAnswer}</MarkdownAnswer>
              {hasCitations ? <Citations citations={citations} /> : null}
            </CardContent>
          </Card>
        </div>
      ) : null}
    </section>
  );
}

function ModelPicker({
  disabled,
  onChange,
  onOpenChange,
  open,
  options,
  value,
}: {
  disabled: boolean;
  onChange: (value: string) => void;
  onOpenChange: (open: boolean) => void;
  open: boolean;
  options: ModelOption[];
  value: string;
}) {
  const selected = options.find((option) => option.id === value) ?? fallbackModelOptions[0];
  const selectedMeta = modelMeta(selected.id);

  return (
    <div className="relative min-w-0" data-model-picker>
      <button
        aria-expanded={open}
        aria-haspopup="listbox"
        className="inline-flex h-11 max-w-[min(72vw,360px)] items-center gap-2 rounded-[var(--radius)] border border-[var(--line-strong)] bg-[var(--surface)] px-2.5 text-left text-[var(--ink)] transition-colors duration-200 hover:border-[var(--primary)] hover:bg-[#edf5ff] focus-visible:border-[var(--primary)] focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[rgba(15,98,254,0.48)] disabled:pointer-events-none disabled:opacity-55"
        disabled={disabled}
        onClick={() => onOpenChange(!open)}
        type="button"
      >
        <ModelAvatar meta={selectedMeta} />
        <span className="grid min-w-0 gap-0.5">
          <span className="truncate text-sm font-semibold leading-none">{selectedMeta.label || selected.label}</span>
          <span className="truncate font-mono text-[11px] leading-none text-[var(--muted)]">
            {selectedMeta.provider} · {selectedMeta.size}
          </span>
        </span>
        <ChevronDown
          aria-hidden="true"
          className={`size-4 shrink-0 text-[var(--muted)] transition-transform duration-200 ${open ? 'rotate-180' : ''}`}
        />
      </button>

      {open ? (
        <div
          className="absolute bottom-[calc(100%+8px)] left-0 z-30 w-[min(88vw,390px)] rounded-[var(--radius)] border border-[var(--line)] bg-[var(--surface)] p-1.5 shadow-[0_18px_48px_rgba(22,22,22,0.14)]"
          role="listbox"
        >
          {options.map((option) => {
            const meta = modelMeta(option.id);
            const selectedOption = option.id === value;
            return (
              <button
                aria-selected={selectedOption}
                className="grid w-full cursor-pointer grid-cols-[auto_minmax(0,1fr)_auto] items-center gap-2 rounded-[var(--radius)] px-2.5 py-2 text-left transition-colors duration-200 hover:bg-[var(--surface-2)] focus-visible:bg-[var(--surface-2)] focus-visible:outline-none aria-selected:bg-[#edf5ff]"
                key={option.id}
                onClick={() => {
                  onChange(option.id);
                  onOpenChange(false);
                }}
                role="option"
                type="button"
              >
                <ModelAvatar meta={meta} />
                <span className="grid min-w-0 gap-1">
                  <span className="truncate text-sm font-semibold leading-tight text-[var(--ink)]">
                    {meta.label || option.label}
                  </span>
                  <span className="truncate font-mono text-[11px] leading-none text-[var(--muted)]">
                    {meta.provider} · {meta.size}
                  </span>
                </span>
                {selectedOption ? <Check aria-hidden="true" className="size-4 text-[var(--primary)]" /> : null}
              </button>
            );
          })}
        </div>
      ) : null}
    </div>
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
          const score = typeof citation.score === 'number' ? ` · ${citation.score.toFixed(3)}` : '';
          return (
            <li
              className="rounded-[var(--radius)] border border-[var(--line)] bg-[var(--surface-2)] p-3"
              key={`${citation.doc_id || 'doc'}-${citation.section_id || index}`}
            >
              {citation.url ? (
                <a
                  className="block text-sm font-semibold text-[var(--primary)] underline decoration-[rgba(15,98,254,0.32)] underline-offset-4 transition-colors duration-200 hover:text-[var(--primary-hover)] hover:decoration-[var(--primary-hover)]"
                  href={citation.url}
                  rel="noopener noreferrer"
                  target="_blank"
                >
                  {citation.citation || 'unknown section'}
                </a>
              ) : (
                <strong className="block text-sm font-semibold text-[var(--ink)]">
                  {citation.citation || 'unknown section'}
                </strong>
              )}
              <span className="mt-1 block font-mono text-[11px] text-[var(--muted)]">
                {citation.doc_id || 'doc'} §{citation.section_id || '?'}
                {score}
              </span>
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
  const existing = window.localStorage.getItem(sessionKey);
  if (existing) {
    return existing;
  }
  const id = window.crypto.randomUUID ? window.crypto.randomUUID() : `${Date.now()}-${Math.random()}`;
  window.localStorage.setItem(sessionKey, id);
  return id;
}

async function loadHealth(): Promise<HealthPayload | null> {
  try {
    const response = await fetch(`${apiBase}/api/health`);
    if (!response.ok) {
      return null;
    }
    return response.json();
  } catch (_error) {
    // The visible UI reports request failures on submit; health stays silent.
    return null;
  }
}

async function ask(question: string, sessionId: string, model: string): Promise<QaPayload> {
  const response = await fetch(`${apiBase}/api/qa`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Session-Id': sessionId,
    },
    body: JSON.stringify({ question, model }),
  });
  if (response.status === 429) {
    throw new Error('rate limit exceeded');
  }
  if (!response.ok) {
    throw new Error(`request failed: ${response.status}`);
  }
  return response.json();
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
  return modelMeta(model).label || model.replace(/:free$/, '');
}

function formatElapsed(ms: number) {
  const elapsed = Math.max(0, ms);
  if (elapsed < 1000) {
    return `${Math.round(elapsed)} ms`;
  }
  return `${(elapsed / 1000).toFixed(elapsed < 10_000 ? 1 : 0)} s`;
}

function modelMeta(model: string): ModelMeta {
  if (model === 'openrouter/free') {
    return {
      provider: 'OpenRouter',
      size: 'router',
      avatar: 'OR',
      swatch: '#0f62fe',
      label: 'Free Models Router',
      iconSrc: '/openrouter-favicon.ico',
    };
  }
  if (model.startsWith('google/gemma-4-31b')) {
    return {
      provider: 'Google',
      size: '31B',
      avatar: 'G',
      swatch: '#1f8a65',
      label: 'Google: Gemma 4 31B (free)',
      iconSrc: '/google-favicon.ico',
    };
  }
  if (model.startsWith('google/gemma-4-26b')) {
    return {
      provider: 'Google',
      size: '26B',
      avatar: 'G',
      swatch: '#1f8a65',
      label: 'Google: Gemma 4 26B A4B (free)',
      iconSrc: '/google-favicon.ico',
    };
  }
  if (model.startsWith('qwen/qwen3-next-80b')) {
    return {
      provider: 'Qwen',
      size: '80B A3B',
      avatar: 'Q',
      swatch: '#8d6d00',
      label: 'Qwen: Qwen3 Next 80B A3B Instruct (free)',
      iconSrc: '/qwen-favicon.ico',
    };
  }
  if (model.startsWith('qwen/qwen3-coder')) {
    return {
      provider: 'Qwen',
      size: '480B A35B',
      avatar: 'Q',
      swatch: '#8d6d00',
      label: 'Qwen: Qwen3 Coder 480B A35B (free)',
      iconSrc: '/qwen-favicon.ico',
    };
  }
  if (model.startsWith('moonshotai/kimi-k2.6')) {
    return {
      provider: 'MoonshotAI',
      size: 'K2.6',
      avatar: 'K',
      swatch: '#161616',
      label: 'MoonshotAI: Kimi K2.6 (free)',
      iconSrc: '/moonshot-favicon.ico',
    };
  }
  if (model.startsWith('openai/gpt-oss-120b')) {
    return {
      provider: 'OpenAI',
      size: '120B',
      avatar: 'AI',
      swatch: '#393939',
      label: 'OpenAI: gpt-oss-120b (free)',
      iconSrc: '/openai-favicon.ico',
    };
  }
  if (model.startsWith('openai/gpt-oss-20b')) {
    return {
      provider: 'OpenAI',
      size: '20B',
      avatar: 'AI',
      swatch: '#393939',
      label: 'OpenAI: gpt-oss-20b (free)',
      iconSrc: '/openai-favicon.ico',
    };
  }
  if (model.startsWith('meta-llama/llama-3.3-70b')) {
    return {
      provider: 'Meta',
      size: '70B',
      avatar: 'M',
      swatch: '#0043ce',
      label: 'Meta: Llama 3.3 70B Instruct (free)',
      iconSrc: '/meta-favicon.svg',
    };
  }
  if (model.startsWith('nvidia/nemotron-3-nano-30b-a3b')) {
    return {
      provider: 'NVIDIA',
      size: '30B A3B',
      avatar: 'NV',
      swatch: '#76b900',
      label: 'NVIDIA: Nemotron 3 Nano 30B A3B (free)',
      iconSrc: '/nvidia-favicon.ico',
    };
  }
  if (model.startsWith('nvidia/nemotron-3-super-120b-a12b')) {
    return {
      provider: 'NVIDIA',
      size: '120B A12B',
      avatar: 'NV',
      swatch: '#76b900',
      label: 'NVIDIA: Nemotron 3 Super (free)',
      iconSrc: '/nvidia-favicon.ico',
    };
  }
  return {
    provider: model.split('/', 1)[0] || 'Model',
    size: model.includes(':free') ? 'free' : 'selected',
    avatar: model.slice(0, 2).toUpperCase(),
    swatch: '#6f6f6f',
    label: model.replace(/:free$/, ''),
  };
}

import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { createInitialQaState, QaClient, qaReducer } from '@app/qa/qa-client';

const sessionId = 'qa-session-fixture';

afterEach(() => {
  cleanup();
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

beforeEach(() => {
  const values = new Map<string, string>();
  Object.defineProperty(window, 'localStorage', {
    configurable: true,
    value: {
      clear: () => values.clear(),
      getItem: (key: string) => values.get(key) ?? null,
      removeItem: (key: string) => values.delete(key),
      setItem: (key: string, value: string) => values.set(key, value),
    },
  });
  window.localStorage.setItem('coquic-qa-session', sessionId);
});

describe('QA reducer state model', () => {
  it('accumulates interleaved channels, keeps metrics independent, and ignores stale events', () => {
    let state = qaReducer(createInitialQaState(), { type: 'submit-start', requestId: 7, startedAt: 1000 });
    state = qaReducer(state, {
      type: 'metadata',
      requestId: 7,
      payload: { rag_confidence: 0.82, citations: [{ citation: 'RFC 9000 Section 1' }] },
    });
    state = qaReducer(state, {
      type: 'channel',
      requestId: 7,
      channel: 'direct',
      payload: { delta: 'Direct ', model: 'direct-model' },
      elapsedMs: 120,
    });
    state = qaReducer(state, {
      type: 'channel',
      requestId: 7,
      channel: 'rag',
      payload: { delta: 'Grounded ', model: 'rag-model' },
      elapsedMs: 180,
    });
    state = qaReducer(state, {
      type: 'channel',
      requestId: 99,
      channel: 'direct',
      payload: { delta: 'stale' },
      elapsedMs: 200,
    });
    state = qaReducer(state, {
      type: 'channel',
      requestId: 7,
      channel: 'direct',
      payload: { delta: 'answer', done: true, usage: { completion_tokens: 5 } },
      elapsedMs: 620,
    });

    expect(state.phase).toBe('streaming');
    expect(state.direct).toMatchObject({
      phase: 'complete',
      answer: 'Direct answer',
      model: 'direct-model',
      metrics: { firstTokenMs: 120, lastTokenMs: 620, completionTokens: 5 },
    });
    expect(state.rag).toMatchObject({
      phase: 'streaming',
      answer: 'Grounded ',
      metrics: { firstTokenMs: 180, lastTokenMs: 180, completionTokens: null },
    });
    expect(state.ragConfidence).toBe(0.82);
    expect(state.citations).toHaveLength(1);
  });

  it.each([
    ['out_of_scope', 'question is not related to QUIC', 'This question is outside the QUIC specification scope.'],
    ['low_retrieval_confidence', 'not enough context', 'The retrieved specification evidence was not strong enough'],
    ['generation_error', 'temporarily unavailable', 'Answer generation is temporarily unavailable.'],
    ['unavailable', 'temporarily unavailable', 'Answer generation is temporarily unavailable.'],
  ])('maps rejected reason %s without discarding returned answers', (reason, publicStatus, reasonText) => {
    const streaming = qaReducer(createInitialQaState(), { type: 'submit-start', requestId: 1, startedAt: 0 });
    const state = qaReducer(streaming, {
      type: 'done',
      requestId: 1,
      elapsedMs: 800,
      payload: {
        accepted: false,
        answer: 'Returned answer',
        reason,
        direct_answer: 'Direct retained',
        rag_answer: 'RAG retained',
      },
    });

    expect(state.phase).toBe('rejected');
    expect(state.statusMessage).toBe(publicStatus);
    expect(state.requestMessage).toContain(reasonText);
    expect(state.direct.answer).toBe('Direct retained');
    expect(state.rag.answer).toBe('RAG retained');
  });

  it('preserves completed evidence when a later suggestion fails', () => {
    let state = qaReducer(createInitialQaState(), { type: 'submit-start', requestId: 1, startedAt: 0 });
    state = qaReducer(state, {
      type: 'done',
      requestId: 1,
      elapsedMs: 500,
      payload: { accepted: true, answer: 'RAG answer', reason: 'answered', direct_answer: 'Direct answer' },
    });
    state = qaReducer(state, { type: 'suggest-start', suggestId: 4 });
    state = qaReducer(state, {
      type: 'suggest-failure',
      suggestId: 4,
      phase: 'rate-limited',
      message: 'Random question limit reached. Try again in a minute.',
      status: 'rate limit exceeded',
    });

    expect(state.phase).toBe('rate-limited');
    expect(state.direct.answer).toBe('Direct answer');
    expect(state.rag.answer).toBe('RAG answer');
  });
});

describe('QA stream and form contract', () => {
  it('generates and stores a session ID when randomUUID is unavailable', () => {
    window.localStorage.removeItem('coquic-qa-session');
    vi.stubGlobal('crypto', {
      getRandomValues: (bytes: Uint8Array) => {
        bytes.forEach((_byte, index) => { bytes[index] = index; });
        return bytes;
      },
    });

    render(<QaClient />);

    expect(window.localStorage.getItem('coquic-qa-session')).toBe('00010203-0405-4607-8809-0a0b0c0d0e0f');
  });

  it('posts the exact stream contract, renders metrics and citations, and supports Ctrl+Enter', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      sseResponse([
        sse('metadata', {
          rag_confidence: 0.84,
          citations: [citationFixture()],
        }),
        sse('direct', { delta: 'Direct ', model: 'deepseek-v4-pro' }),
        sse('rag', { delta: 'Grounded ' }),
        sse('direct', { delta: 'answer.', done: true, usage: { completion_tokens: 5 } }),
        sse('rag', { delta: 'answer.', done: true, usage: { completion_tokens: 6 } }),
        sse('done', donePayload()),
      ]),
    );
    vi.stubGlobal('fetch', fetchMock);

    render(<QaClient />);
    const question = screen.getByRole('textbox', { name: 'Question' });
    fireEvent.change(question, { target: { value: 'How does ACK delay work?' } });
    fireEvent.keyDown(question, { key: 'Enter', ctrlKey: true });

    await waitFor(() => expect(screen.getByText('answered')).toBeInTheDocument());

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock).toHaveBeenCalledWith(
      '/rag-api/api/qa/stream',
      expect.objectContaining({
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'text/event-stream',
          'X-Session-Id': sessionId,
        },
        body: JSON.stringify({ question: 'How does ACK delay work?' }),
        signal: expect.any(AbortSignal),
      }),
    );
    const desktop = document.querySelector('[data-qa-results-view="desktop"]')!;
    expect(within(desktop as HTMLElement).getByText('Direct final answer.')).toBeInTheDocument();
    expect(within(desktop as HTMLElement).getByText('RAG final answer.')).toBeInTheDocument();
    expect(within(desktop as HTMLElement).getByText('15 tok')).toBeInTheDocument();
    expect(within(desktop as HTMLElement).getByText('17 tok')).toBeInTheDocument();
    expect(within(desktop as HTMLElement).getByText('84% (High)')).toBeInTheDocument();
    expect(within(desktop as HTMLElement).getByRole('link', { name: 'RFC 9000 Section 13.2' })).toHaveAttribute(
      'href',
      'https://www.rfc-editor.org/rfc/rfc9000.html#section-13.2',
    );
    expect(within(desktop as HTMLElement).getByText('Similarity 0.913')).toHaveAccessibleName(
      'Retrieval similarity 0.913',
    );
  });

  it('keeps malformed events inert and accepts a final event without a trailing separator', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      sseResponse([sse('metadata', { rag_confidence: 0.2 }), 'event: direct\ndata: {not-json}', sse('done', donePayload())], false),
    );
    vi.stubGlobal('fetch', fetchMock);
    render(<QaClient />);

    ask('What is QUIC?');
    await waitFor(() => expect(screen.getByText('answered')).toBeInTheDocument());
    expect(document.querySelector('[data-qa-phase="completed"]')).toBeInTheDocument();
  });

  it.each([
    ['rate-limited', () => new Response('', { status: 429 }), 'Request limit reached. Try again in a minute.'],
    ['HTTP failure', () => new Response('', { status: 500 }), 'The specification QA request could not be completed.'],
    ['missing body', () => new Response(null, { status: 200 }), 'The specification QA request could not be completed.'],
    ['ended before done', () => sseResponse([]), 'The specification QA request could not be completed.'],
    ['stream error', () => sseResponse([sse('error', { detail: 'provider' })]), 'The specification QA request could not be completed.'],
  ])('shows one recovery state for %s instead of duplicate model answers', async (_name, response, message) => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response()));
    render(<QaClient />);

    ask('How does QUIC recover loss?');
    await waitFor(() => expect(document.querySelector('[data-qa-request-status]')).toHaveTextContent(message));
    expect(screen.getByRole('button', { name: 'Retry' })).toBeInTheDocument();
    expect(screen.queryByText('request failed: 500')).not.toBeInTheDocument();
    expect(document.querySelectorAll('[data-channel]')).toHaveLength(0);
  });

  it('classifies a network rejection as offline', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new TypeError('Failed to fetch')));
    render(<QaClient />);

    ask('How does QUIC recover loss?');
    await waitFor(() =>
      expect(document.querySelector('[data-qa-request-status]')).toHaveTextContent(
        'Unable to reach specification QA. Check your connection and try again.',
      ),
    );
    expect(document.querySelector('[data-qa-phase="offline"]')).toBeInTheDocument();
  });

  it('aborts the old stream on a superseding submission and on unmount', async () => {
    const pendingSignals: AbortSignal[] = [];
    const fetchMock = vi.fn((_url: string, init?: RequestInit) => {
      const signal = init?.signal as AbortSignal;
      pendingSignals.push(signal);
      return abortableResponse(signal);
    });
    vi.stubGlobal('fetch', fetchMock);
    const { unmount } = render(<QaClient />);
    const textbox = screen.getByRole('textbox', { name: 'Question' });
    const form = textbox.closest('form')!;

    fireEvent.change(textbox, { target: { value: 'First question' } });
    fireEvent.submit(form);
    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1));
    fireEvent.change(textbox, { target: { value: 'Second question' } });
    fireEvent.submit(form);
    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(2));

    expect(pendingSignals[0]?.aborted).toBe(true);
    expect(pendingSignals[1]?.aborted).toBe(false);
    unmount();
    expect(pendingSignals[1]?.aborted).toBe(true);
  });

  it('announces required input without starting a request', () => {
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
    render(<QaClient />);

    fireEvent.submit(screen.getByRole('textbox', { name: 'Question' }).closest('form')!);
    expect(screen.getByRole('alert')).toHaveTextContent('Enter a QUIC specification question before asking.');
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

describe('QA auxiliary controls', () => {
  it('uses the random-question contract and distinguishes success, 429, and generic errors', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify({ question: 'How are packet numbers encoded?' }), { status: 200 }))
      .mockResolvedValueOnce(new Response('', { status: 429 }))
      .mockResolvedValueOnce(new Response('', { status: 500 }));
    vi.stubGlobal('fetch', fetchMock);
    render(<QaClient />);

    const suggest = screen.getByRole('button', { name: 'Suggest question' });
    fireEvent.click(suggest);
    await waitFor(() => expect(screen.getByRole('textbox', { name: 'Question' })).toHaveValue('How are packet numbers encoded?'));
    expect(fetchMock).toHaveBeenNthCalledWith(1, '/rag-api/api/questions/random', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Session-Id': sessionId },
      signal: expect.any(AbortSignal),
    });

    fireEvent.click(suggest);
    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('Random question limit reached.'));
    fireEvent.click(suggest);
    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('temporarily unavailable'));
  });

  it('supports touch disclosure and announces copy success and failure', async () => {
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: { writeText: vi.fn().mockResolvedValueOnce(undefined).mockRejectedValueOnce(new Error('denied')) },
    });
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(sseResponse([sse('done', donePayload())])));
    render(<QaClient />);

    const privacy = screen.getByRole('button', { name: 'Privacy notice' });
    expect(privacy).toHaveAttribute('aria-expanded', 'false');
    fireEvent.click(privacy);
    expect(privacy).toHaveAttribute('aria-expanded', 'true');

    ask('What is QUIC?');
    await waitFor(() => expect(screen.getByText('answered')).toBeInTheDocument());
    const desktop = document.querySelector('[data-qa-results-view="desktop"]')!;
    const copyButtons = within(desktop as HTMLElement).getAllByRole('button', { name: /^Copy/ });
    fireEvent.click(copyButtons[0]!);
    await waitFor(() => expect(within(desktop as HTMLElement).getByText('Direct answer copied to clipboard.')).toBeInTheDocument());
    fireEvent.click(copyButtons[1]!);
    await waitFor(() => expect(within(desktop as HTMLElement).getByText('Unable to copy With RAG answer. Try again.')).toBeInTheDocument());
  });
});

function ask(question: string) {
  const textbox = screen.getByRole('textbox', { name: 'Question' });
  fireEvent.change(textbox, { target: { value: question } });
  fireEvent.submit(textbox.closest('form')!);
}

function sse(event: string, data: unknown) {
  return `event: ${event}\ndata: ${JSON.stringify(data)}`;
}

function sseResponse(events: string[], trailingSeparator = true) {
  const body = `${events.join('\n\n')}${trailingSeparator ? '\n\n' : ''}`;
  return new Response(body, { status: 200, headers: { 'Content-Type': 'text/event-stream' } });
}

function citationFixture() {
  return {
    citation: 'RFC 9000 Section 13.2',
    doc_id: 'rfc9000',
    section_id: '13.2',
    title: 'Generating Acknowledgements',
    score: 0.913,
    text: 'An endpoint SHOULD send an ACK frame after receiving at least two ack-eliciting packets.',
    url: 'https://www.rfc-editor.org/rfc/rfc9000.html#section-13.2',
  };
}

function donePayload() {
  return {
    accepted: true,
    answer: 'RAG final answer.',
    reason: 'answered',
    direct_answer: 'Direct final answer.',
    direct_usage: { prompt_tokens: 10, completion_tokens: 5, total_tokens: 15 },
    direct_model: 'deepseek-v4-pro',
    rag_answer: 'RAG final answer.',
    rag_usage: { prompt_tokens: 11, completion_tokens: 6, total_tokens: 17 },
    rag_model: 'deepseek-v4-pro',
    rag_confidence: 0.84,
    citations: [citationFixture()],
  };
}

function abortableResponse(signal: AbortSignal): Promise<Response> {
  return new Promise((_resolve, reject) => {
    signal.addEventListener('abort', () => reject(new DOMException('Aborted', 'AbortError')), { once: true });
  });
}

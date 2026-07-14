import type { Page } from '@playwright/test';

type QaScenario = {
  events?: Array<{ event: string; data: Record<string, unknown> }>;
  intervalMs?: number;
  streamStatus?: number;
  streamNetworkError?: boolean;
  streamErrorAfter?: number;
  randomQuestion?: string;
  randomStatus?: number;
};

export const qaCitation = {
  citation: 'RFC 9000 Section 13.2',
  doc_id: 'rfc9000',
  section_id: '13.2',
  title: 'Generating Acknowledgements',
  score: 0.913,
  text: Array.from(
    { length: 18 },
    (_, index) =>
      `Evidence line ${index + 1}: An endpoint SHOULD send an ACK frame after receiving at least two ack-eliciting packets.`,
  ).join('\n'),
  url: 'https://www.rfc-editor.org/rfc/rfc9000.html#section-13.2',
};

export function successfulQaEvents() {
  return [
    { event: 'metadata', data: { rag_confidence: 0.84, citations: [qaCitation] } },
    { event: 'direct', data: { delta: 'Direct partial ', model: 'deepseek-v4-pro' } },
    { event: 'rag', data: { delta: 'Grounded partial ', model: 'deepseek-v4-pro' } },
    { event: 'direct', data: { delta: 'answer.', done: true, usage: { completion_tokens: 5 } } },
    { event: 'rag', data: { delta: 'answer.', done: true, usage: { completion_tokens: 6 } } },
    {
      event: 'done',
      data: {
        answer: 'RAG final answer with **specification evidence**.',
        accepted: true,
        reason: 'answered',
        direct_answer: 'Direct final answer without retrieval.',
        direct_usage: { prompt_tokens: 10, completion_tokens: 5, total_tokens: 15 },
        direct_model: 'deepseek-v4-pro',
        rag_answer: 'RAG final answer with **specification evidence**.',
        rag_usage: { prompt_tokens: 11, completion_tokens: 6, total_tokens: 17 },
        rag_model: 'deepseek-v4-pro',
        rag_confidence: 0.84,
        citations: [qaCitation],
      },
    },
  ];
}

export function rejectedQaEvents(reason: string) {
  return [
    {
      event: 'done',
      data: {
        answer: 'No supported answer.',
        accepted: false,
        reason,
        direct_answer: 'Direct response retained.',
        rag_answer: 'Grounded response retained.',
        citations: [],
      },
    },
  ];
}

export function wideMarkdownQaEvents() {
  const longCodeLine = `const packet = "${'c'.repeat(420)}";`;
  const longCellA = `transport-${'a'.repeat(180)}`;
  const longCellB = `recovery-${'b'.repeat(180)}`;
  return [
    {
      event: 'done',
      data: {
        answer: `| Field | Value |\n| --- | --- |\n| ${longCellA} | ${longCellB} |`,
        accepted: true,
        reason: 'answered',
        direct_answer: `\`\`\`typescript\n${longCodeLine}\n\`\`\``,
        rag_answer: `| Field | Value |\n| --- | --- |\n| ${longCellA} | ${longCellB} |`,
        citations: [],
      },
    },
  ];
}

export async function installQaFixture(page: Page, scenario: QaScenario = {}) {
  await page.addInitScript((fixture) => {
    const nativeFetch = window.fetch.bind(window);
    const requests: Array<{ body: string | null; headers: Record<string, string>; method: string; url: string }> = [];
    Object.defineProperty(window, '__qaRequests', { configurable: true, value: requests });
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: {
        writeText: async (text: string) => {
          window.localStorage.setItem('coquic-qa-copied', text);
        },
      },
    });

    window.fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
      if (!url.startsWith('/rag-api/')) return nativeFetch(input, init);

      requests.push({
        body: typeof init?.body === 'string' ? init.body : null,
        headers: Object.fromEntries(new Headers(init?.headers).entries()),
        method: init?.method ?? 'GET',
        url,
      });

      if (url.endsWith('/api/questions/random')) {
        return new Response(
          JSON.stringify({ question: fixture.randomQuestion ?? 'How are QUIC packet numbers encoded?' }),
          { status: fixture.randomStatus ?? 200, headers: { 'Content-Type': 'application/json' } },
        );
      }

      if (fixture.streamNetworkError) throw new TypeError('Failed to fetch');
      if (fixture.streamStatus && fixture.streamStatus !== 200) {
        return new Response('', { status: fixture.streamStatus });
      }

      const encoder = new TextEncoder();
      const events = fixture.events ?? [];
      const body = new ReadableStream<Uint8Array>({
        start(controller) {
          let eventIndex = 0;
          let timer: number | null = null;
          const signal = init?.signal;
          const abort = () => {
            if (timer !== null) window.clearTimeout(timer);
            controller.error(new DOMException('Aborted', 'AbortError'));
          };
          signal?.addEventListener('abort', abort, { once: true });

          const sendNext = () => {
            if (signal?.aborted) return;
            if (fixture.streamErrorAfter === eventIndex) {
              controller.error(new Error('fixture stream failure'));
              return;
            }
            const next = events[eventIndex];
            if (!next) {
              signal?.removeEventListener('abort', abort);
              controller.close();
              return;
            }
            controller.enqueue(encoder.encode(`event: ${next.event}\ndata: ${JSON.stringify(next.data)}\n\n`));
            eventIndex += 1;
            timer = window.setTimeout(sendNext, fixture.intervalMs ?? 0);
          };
          sendNext();
        },
      });
      return new Response(body, { status: 200, headers: { 'Content-Type': 'text/event-stream' } });
    };
  }, scenario);
}

export async function qaRequests(page: Page) {
  return page.evaluate(() =>
    (window as typeof window & {
      __qaRequests: Array<{ body: string | null; headers: Record<string, string>; method: string; url: string }>;
    }).__qaRequests,
  );
}

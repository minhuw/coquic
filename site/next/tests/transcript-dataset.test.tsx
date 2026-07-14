import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const router = vi.hoisted(() => ({ push: vi.fn(), replace: vi.fn() }));
let currentSearch = '';

vi.mock('next/navigation', () => ({
  usePathname: () => '/transcript',
  useRouter: () => router,
  useSearchParams: () => new URLSearchParams(currentSearch),
}));

import {
  collectionScrollKey,
  listScrollStorageKey,
  readOwnedParams,
  searchDebounceMs,
  TranscriptDataset,
} from '@app/transcript/transcript-dataset';
import {
  transcriptDetailResponse,
  transcriptEmptySearch,
  transcriptRecords,
  transcriptSearchResponse,
  transcriptSessions,
} from './e2e/fixtures/transcript';

function jsonResponse(body: unknown, status = 200) {
  return Promise.resolve(new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } }));
}

function mockFetch(handler: (url: string, init?: RequestInit) => Promise<Response>) {
  return vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => handler(String(input), init));
}

beforeEach(() => {
  currentSearch = '';
  router.push.mockReset();
  router.replace.mockReset();
  window.history.replaceState({}, '', '/transcript');
  window.sessionStorage.clear();
});

afterEach(() => {
  cleanup();
  vi.useRealTimers();
  vi.restoreAllMocks();
});

describe('transcript URL model', () => {
  it('normalizes only valid owned values and makes a sorted collection scroll key', () => {
    const parsed = readOwnedParams(new URLSearchParams('q=%20quic%20&from=2026-02-30&to=2026-06-30&page=3.8&session=%20abc%20'));
    expect(parsed).toEqual({ q: 'quic', from: '', to: '2026-06-30', page: 3, session: 'abc' });
    expect(collectionScrollKey(parsed)).toBe('page=3&q=quic&to=2026-06-30');
  });

  it('canonicalizes reversed valid dates before requesting and preserves unrelated params', async () => {
    currentSearch = 'utm=kept&from=2026-06-30&to=2026-05-01';
    const fetchMock = mockFetch((url) => {
      expect(url).toBe('/transcript/api/search?page=1&from=2026-05-01&to=2026-06-30');
      return jsonResponse(transcriptSearchResponse({ from: '2026-05-01', to: '2026-06-30' }));
    });
    render(<TranscriptDataset />);

    await screen.findByText('Transcript session 1 with a deliberately descriptive label');
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(router.replace).toHaveBeenCalledWith('/transcript?utm=kept&from=2026-05-01&to=2026-06-30', { scroll: false });
    fireEvent.click(screen.getByRole('button', { name: /Date range/ }));
    expect(screen.getByLabelText('Filter transcripts from date')).toHaveValue('2026-05-01');
    expect(screen.getByLabelText('Filter transcripts to date')).toHaveValue('2026-06-30');
  });

  it('does not treat a filtered manifest range as full-dataset input bounds', async () => {
    currentSearch = 'from=2026-05-01';
    mockFetch(() => jsonResponse(transcriptSearchResponse({
      from: '2026-05-01',
      manifest: {
        ...transcriptSearchResponse().manifest,
        dateRange: { start: '2026-05-04T08:00:00.000Z', end: '2026-06-30T12:00:00.000Z' },
      },
    })));
    render(<TranscriptDataset />);

    await screen.findByText('Transcript session 1 with a deliberately descriptive label');
    fireEvent.click(screen.getByRole('button', { name: /Date range/ }));
    const from = screen.getByLabelText('Filter transcripts from date');
    const to = screen.getByLabelText('Filter transcripts to date');
    expect(from).toHaveValue('2026-05-01');
    expect(from).not.toHaveAttribute('min');
    expect(from).not.toHaveAttribute('max');
    expect(to).toHaveAttribute('min', '2026-05-01');
    expect(to).not.toHaveAttribute('max');
  });

  it('requests page 1, renders a populated collection, and never auto-selects row one', async () => {
    const fetchMock = mockFetch((url) => {
      expect(url).toBe('/transcript/api/search?page=1');
      return jsonResponse(transcriptSearchResponse());
    });
    render(<TranscriptDataset />);

    expect(await screen.findByText('Transcript session 1 with a deliberately descriptive label')).toBeVisible();
    expect(screen.getByText('Select a transcript')).toBeVisible();
    expect(screen.queryByLabelText('Complete transcript conversation')).not.toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('debounces search replacement, resets navigation state, and preserves unrelated params', async () => {
    vi.useFakeTimers();
    currentSearch = 'utm=kept&page=2&session=old';
    mockFetch(() => jsonResponse(transcriptSearchResponse({ page: 2 })));
    render(<TranscriptDataset />);
    await act(async () => Promise.resolve());

    fireEvent.change(screen.getByRole('searchbox', { name: 'Search transcript sessions' }), { target: { value: '  congestion  ' } });
    await act(async () => vi.advanceTimersByTimeAsync(searchDebounceMs - 1));
    expect(router.replace).not.toHaveBeenCalled();
    await act(async () => vi.advanceTimersByTimeAsync(1));

    expect(router.replace).toHaveBeenCalledWith('/transcript?utm=kept&q=congestion', { scroll: false });
  });

  it('pushes validated selection and pagination while preserving filters', async () => {
    currentSearch = 'q=quic&from=2026-06-01&to=2026-06-30';
    mockFetch(() => jsonResponse(transcriptSearchResponse({ query: 'quic', from: '2026-06-01', to: '2026-06-30' })));
    render(<TranscriptDataset />);

    fireEvent.click(await screen.findByText('Transcript session 1 with a deliberately descriptive label'));
    expect(router.push).toHaveBeenCalledWith('/transcript?q=quic&from=2026-06-01&to=2026-06-30&session=public-session-1', { scroll: false });

    fireEvent.click(screen.getByRole('button', { name: 'Next' }));
    expect(router.push).toHaveBeenLastCalledWith('/transcript?q=quic&from=2026-06-01&to=2026-06-30&page=2', { scroll: false });
  });

  it('keeps an explicit deep link on 404 and removes only session on Back to results', async () => {
    currentSearch = 'utm=kept&q=quic&session=missing-public-id';
    mockFetch((url) => url.startsWith('/transcript/api/search') ? jsonResponse(transcriptSearchResponse({ query: 'quic' })) : jsonResponse({ detail: 'not found' }, 404));
    render(<TranscriptDataset />);

    expect(await screen.findByText('Transcript not found')).toBeVisible();
    expect(screen.getByText('No public transcript matches missing-public-id.')).toBeVisible();
    fireEvent.click(within(screen.getByLabelText('Selected transcript preview')).getByRole('button', { name: 'Back to results' }));
    expect(router.replace).toHaveBeenCalledWith('/transcript?utm=kept&q=quic', { scroll: false });
  });

  it('distinguishes empty and unavailable collections without fabricating a manifest', async () => {
    const fetchMock = mockFetch(() => jsonResponse({ detail: 'unavailable' }, 503));
    render(<TranscriptDataset />);
    expect(await screen.findByText('The transcript index is currently unavailable.')).toBeVisible();
    expect(screen.queryByText('No transcripts found')).not.toBeInTheDocument();
    expect(screen.getByText('Archive unavailable')).toBeVisible();

    cleanup();
    fetchMock.mockImplementation(() => jsonResponse(transcriptEmptySearch));
    render(<TranscriptDataset />);
    expect(await screen.findByText('No transcripts found')).toBeVisible();
  });

  it('requests 80 records, exposes raw downloads, and preserves records when load more fails', async () => {
    currentSearch = 'session=public-session-1';
    let detailCalls = 0;
    mockFetch((url) => {
      if (url.startsWith('/transcript/api/search')) return jsonResponse(transcriptSearchResponse());
      detailCalls += 1;
      if (detailCalls === 1) {
        expect(url).toBe('/transcript/api/session/public-session-1?limit=80');
        return jsonResponse(transcriptDetailResponse());
      }
      expect(url).toBe('/transcript/api/session/public-session-1?cursor=2&limit=80');
      return jsonResponse({ detail: 'failed' }, 500);
    });
    render(<TranscriptDataset />);

    expect(await screen.findByText(transcriptRecords[0].text)).toBeVisible();
    expect(screen.getByRole('link', { name: 'JSONL' })).toHaveAttribute('href', '/transcript/api/session/public-session-1/raw');
    fireEvent.click(screen.getByRole('button', { name: 'Load more' }));
    expect(await screen.findByRole('button', { name: 'Retry load more' })).toBeVisible();
    expect(screen.getByText(transcriptRecords[0].text)).toBeVisible();
    expect(screen.getByRole('alert')).toHaveTextContent('More records could not be loaded.');
  });

  it('appends successful cursor records in order and marks the transcript exhausted', async () => {
    currentSearch = 'session=public-session-1';
    let detailCalls = 0;
    mockFetch((url) => {
      if (url.startsWith('/transcript/api/search')) return jsonResponse(transcriptSearchResponse());
      detailCalls += 1;
      if (detailCalls === 1) return jsonResponse(transcriptDetailResponse());
      return jsonResponse(transcriptDetailResponse({
        records: [{ ...transcriptRecords[1], line: 3, text: 'Second cursor record.' }],
        hasMore: false,
        nextCursor: 3,
      }));
    });
    render(<TranscriptDataset />);

    fireEvent.click(await screen.findByRole('button', { name: 'Load more' }));
    const first = await screen.findByText(transcriptRecords[0].text);
    const appended = await screen.findByText('Second cursor record.');
    expect(first.compareDocumentPosition(appended) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(screen.getByText('End of loaded transcript')).toBeVisible();
    expect(screen.queryByRole('button', { name: 'Load more' })).not.toBeInTheDocument();
  });

  it('renders a factual metadata-only detail without inventing records', async () => {
    currentSearch = 'session=public-session-1';
    mockFetch((url) => url.startsWith('/transcript/api/search')
      ? jsonResponse(transcriptSearchResponse())
      : jsonResponse(transcriptDetailResponse({ records: [], hasMore: false, nextCursor: 120 })));
    render(<TranscriptDataset />);

    expect(await screen.findByText('Metadata only')).toBeVisible();
    expect(screen.getByText('This transcript has no displayable conversation records.')).toBeVisible();
    expect(screen.getByText('End of loaded transcript')).toBeVisible();
  });

  it('never renders the previous session records under a new selection', async () => {
    currentSearch = 'session=public-session-1';
    mockFetch((url) => {
      if (url.startsWith('/transcript/api/search')) return jsonResponse(transcriptSearchResponse());
      if (url.includes('public-session-1')) return jsonResponse(transcriptDetailResponse());
      return new Promise<Response>(() => undefined);
    });
    const view = render(<TranscriptDataset />);
    expect(await screen.findByText(transcriptRecords[0].text)).toBeVisible();

    currentSearch = 'session=public-session-2';
    view.rerender(<TranscriptDataset />);
    expect(screen.getByText('public-session-2')).toBeVisible();
    expect(screen.getByText('Loading transcript')).toBeVisible();
    expect(screen.queryByText(transcriptRecords[0].text)).not.toBeInTheDocument();
  });

  it('aborts the stale collection request when URL filters change', async () => {
    let firstSignal: AbortSignal | undefined;
    mockFetch((url, init) => {
      if (url.includes('q=new')) return jsonResponse(transcriptSearchResponse({ query: 'new' }));
      firstSignal = init?.signal as AbortSignal;
      return new Promise<Response>(() => undefined);
    });
    const view = render(<TranscriptDataset />);
    await waitFor(() => expect(firstSignal).toBeDefined());

    currentSearch = 'q=new';
    view.rerender(<TranscriptDataset />);
    await screen.findByText('Transcript session 1 with a deliberately descriptive label');
    expect(firstSignal?.aborted).toBe(true);
  });

  it('stores list scroll by the canonical collection key before selection', async () => {
    mockFetch(() => jsonResponse(transcriptSearchResponse()));
    render(<TranscriptDataset />);
    const list = await screen.findByLabelText('Transcript sessions');
    Object.defineProperty(list, 'scrollTop', { configurable: true, value: 177, writable: true });
    fireEvent.scroll(list);
    expect(JSON.parse(window.sessionStorage.getItem(listScrollStorageKey) ?? '{}')).toEqual({ '': 177 });

    fireEvent.click(screen.getByText('Transcript session 1 with a deliberately descriptive label'));
    expect(JSON.parse(window.sessionStorage.getItem(listScrollStorageKey) ?? '{}')).toEqual({ '': 177 });
  });
});

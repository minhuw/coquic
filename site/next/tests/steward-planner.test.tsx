import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { StewardPlannerLive } from '@/components/steward-planner';
import type { PublicArtifact, PublicPlannerRun, PublicStewardMonitor } from '@/generated/steward-public';

import { plannerMonitor, producerFixture } from './fixtures';

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe('Steward planner history', () => {
  it('loads the exact public endpoint without caching and preserves payload order', async () => {
    const monitor = plannerMonitor();
    const fetchMock = vi.fn().mockResolvedValue(responseFor(monitor));
    vi.stubGlobal('fetch', fetchMock);

    render(<StewardPlannerLive />);

    expect(screen.getByRole('heading', { level: 1, name: 'Planner history' })).toBeInTheDocument();
    expect(document.querySelector('[data-steward-module="planner"]')).toBeInTheDocument();
    expect(screen.getByText('Loading planner history')).toBeInTheDocument();
    expectPlannerSummary('Loading', 'Loading', 'Loading');
    expect(await screen.findByText('Page 1 of 2')).toBeInTheDocument();
    expectPlannerSummary('11', 'window truncated', formatTimestamp(monitor.generated_at));
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock).toHaveBeenCalledWith('/steward/status', { cache: 'no-store' });

    const firstPageRuns = screen.getAllByRole('article');
    expect(firstPageRuns).toHaveLength(10);
    expect(within(firstPageRuns[0]).getByRole('heading', { name: monitor.planner_runs[0]?.id })).toBeInTheDocument();
    expect(within(firstPageRuns[9]).getByRole('heading', { name: monitor.planner_runs[9]?.id })).toBeInTheDocument();

    const next = screen.getByRole('button', { name: 'Next planner history page' });
    next.focus();
    fireEvent.click(next);
    expect(screen.getByText('Page 2 of 2')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Previous planner history page' })).toHaveFocus();
    expect(screen.getAllByRole('article')).toHaveLength(1);
    expect(screen.getByRole('heading', { name: monitor.planner_runs[10]?.id })).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'Previous planner history page' }));
    expect(screen.getByText('Page 1 of 2')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Previous planner history page' })).toBeDisabled();
  });

  it('renders one run without pagination ambiguity and reports a truncated publication window', async () => {
    const monitor = monitorWithRuns([plannerRun({ id: 'only-run' })]);
    monitor.planner_runs_truncated = true;
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(responseFor(monitor)));

    render(<StewardPlannerLive />);

    expect(await screen.findByRole('heading', { name: 'only-run' })).toBeInTheDocument();
    expectPlannerSummary('1', 'window truncated', formatTimestamp(monitor.generated_at));
    expect(screen.getByText('Page 1 of 1')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Previous planner history page' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Next planner history page' })).toBeDisabled();
  });

  it('shows HTTP, decode, and empty states with factual diagnostics', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response('unavailable', { status: 503 })));
    const { unmount } = render(<StewardPlannerLive />);
    expect(await screen.findByText('Planner history unavailable')).toBeInTheDocument();
    expect(screen.getByText('status unavailable')).toBeInTheDocument();
    expectPlannerSummary('Unavailable', 'Unavailable', 'Unavailable');

    unmount();
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response('{not-json')));
    const decoded = render(<StewardPlannerLive />);
    expect(await screen.findByText('malformed')).toBeInTheDocument();
    expectPlannerSummary('Unavailable', 'Unavailable', 'Unavailable');

    decoded.unmount();
    const emptyMonitor = monitorWithRuns([]);
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(responseFor(emptyMonitor)));
    render(<StewardPlannerLive />);
    expect(await screen.findByText('No planner runs published')).toBeInTheDocument();
    expect(screen.getByText('The daemon has not published a signal-planner iteration.')).toBeInTheDocument();
    expectPlannerSummary('0', 'complete', formatTimestamp(emptyMonitor.generated_at));
  });

  it('renders every status, exact metrics, diagnostics, long IDs, signals, and timestamps', async () => {
    const longId = `planner-${'identifier-'.repeat(12)}end`;
    const longSignalId = `wi-${'signal-'.repeat(18)}end`;
    const runs: PublicPlannerRun[] = [
      plannerRun({ id: longId, status: 'running', completed_at: null, consumed_signal_ids: [longSignalId] }),
      plannerRun({ id: 'succeeded-run', status: 'succeeded', accepted_count: 3, proposed_count: 5 }),
      plannerRun({ id: 'failed-run', status: 'failed', diagnostics: diagnostics('provider failed', 17, 'provider_error') }),
      plannerRun({ id: 'invalid-run', status: 'invalid', diagnostics: diagnostics('', 2, 'invalid_output') }),
    ];
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(responseFor(monitorWithRuns(runs))));

    render(<StewardPlannerLive />);

    await screen.findByRole('heading', { name: longId });
    const [running, succeeded, failed, invalid] = screen.getAllByRole('article');
    if (!running || !succeeded || !failed || !invalid) throw new Error('expected all planner status rows');
    expect(within(running).getByText('running')).toBeInTheDocument();
    expect(within(running).getByText(/in progress$/)).toBeInTheDocument();
    expect(within(running).getByText(`Consumed: ${longSignalId}`)).toBeInTheDocument();
    expect(within(running).getByText(formatTimestamp('2026-07-13T11:50:00Z'), { exact: false })).toBeInTheDocument();

    expect(within(succeeded).getByText('3')).toBeInTheDocument();
    expect(within(succeeded).getByText('5')).toBeInTheDocument();
    expect(within(succeeded).getByText('Exit').parentElement).toHaveTextContent('Exit0');

    expect(within(failed).getByText('provider failed')).toBeInTheDocument();
    expect(within(invalid).getByText('invalid_output')).toBeInTheDocument();
    expect(within(succeeded).getByText('succeeded')).toBeInTheDocument();
    expect(within(failed).getByText('failed')).toBeInTheDocument();
    expect(within(invalid).getByText('invalid')).toBeInTheDocument();
  });

  it('keeps artifact availability, missing, text, and truncation states explicit', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    vi.stubGlobal('navigator', { clipboard: { writeText } });
    const run = plannerRun({
      id: 'artifact-run',
      artifacts: {
        transcript: artifact({
          availability: 'redacted',
          text: 'first  line\nsecond    line with retained whitespace',
          truncated: true,
        }),
        last_message: null,
      },
    });
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(responseFor(monitorWithRuns([run]))));

    render(<StewardPlannerLive />);
    const disclosure = await screen.findByText('Artifacts');
    fireEvent.click(disclosure);

    expect(screen.getByText('redacted / truncated')).toBeInTheDocument();
    expect(screen.getByText((_, element) => (
      element?.classList.contains('code-token') === true && element.textContent === 'first  line'
    ))).toBeInTheDocument();
    expect(screen.getByText((_, element) => (
      element?.classList.contains('code-token') === true
      && element.textContent === 'second    line with retained whitespace'
    ))).toBeInTheDocument();
    expect(screen.getByText('Not produced')).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'Copy code' }));
    await waitFor(() => expect(writeText).toHaveBeenCalledWith('first  line\nsecond    line with retained whitespace'));
    expect(screen.getByRole('button', { name: 'Code copied' })).toBeInTheDocument();
  });
});

function expectPlannerSummary(visibleRuns: string, publishedWindow: string, lastUpdate: string) {
  const summary = within(screen.getByLabelText('Planner history summary'));
  expect(summary.getByText('Visible runs').parentElement).toHaveTextContent(`Visible runs${visibleRuns}`);
  expect(summary.getByText('Published window').parentElement).toHaveTextContent(`Published window${publishedWindow}`);
  expect(summary.getByText('Last update').parentElement).toHaveTextContent(`Last update${lastUpdate}`);
}

function responseFor(monitor: PublicStewardMonitor) {
  return new Response(JSON.stringify(monitor), { headers: { 'Content-Type': 'application/json' } });
}

function monitorWithRuns(runs: PublicPlannerRun[]) {
  const monitor = producerFixture('idle');
  monitor.planner_runs = runs;
  monitor.planner_runs_truncated = false;
  return monitor;
}

function plannerRun(overrides: Partial<PublicPlannerRun> = {}): PublicPlannerRun {
  return {
    id: 'planner-run',
    status: 'succeeded',
    started_at: '2026-07-13T11:50:00Z',
    completed_at: '2026-07-13T11:50:30Z',
    accepted_count: 1,
    proposed_count: 2,
    consumed_signal_ids: [],
    diagnostics: diagnostics('planner completed', 0, 'none'),
    artifacts: { transcript: artifact(), last_message: artifact({ text: 'accepted one public signal' }) },
    ...overrides,
  };
}

function diagnostics(
  summary: string,
  exit_code: number | null,
  error_category: PublicPlannerRun['diagnostics']['error_category'],
): PublicPlannerRun['diagnostics'] {
  return { summary, exit_code, error_category, last_message_present: true };
}

function artifact(overrides: Partial<NonNullable<PublicArtifact>> = {}): NonNullable<PublicArtifact> {
  return {
    availability: 'available',
    mode: 'redacted',
    text: 'planner output',
    size_bytes: 14,
    original_size_bytes: 14,
    truncated: false,
    sha256: null,
    url: null,
    ...overrides,
  };
}

function formatTimestamp(value: string) {
  return new Date(value).toLocaleString(undefined, {
    day: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
    month: 'short',
    second: '2-digit',
    timeZoneName: 'short',
    year: 'numeric',
  });
}

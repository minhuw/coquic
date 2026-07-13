import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  loadPublicStewardTaskDetail,
  StewardDashboard,
  StewardFreshness,
  StewardTaskDetail,
} from '@/components/steward-public';
import { CodeBlock } from '@/components/steward-code-block';
import { StewardPlannerLive } from '@/components/steward-planner';

import {
  asLegacyStewardState,
  plannerMonitor,
  producerFixture,
  producerFixtureText,
  signalMonitor,
  taskWindow,
} from './fixtures';

afterEach(() => {
  cleanup();
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

describe('Steward retained read views', () => {
  it('renders the empty, loading, offline, and incompatible dashboard states', () => {
    const { rerender } = render(<StewardDashboard loading state={null} />);
    expect(screen.getByText('Loading the latest Steward snapshot.')).toBeInTheDocument();
    expect(screen.getByText('Offline')).toBeInTheDocument();

    rerender(<StewardDashboard fetchError="incompatible" state={null} />);
    expect(screen.getByText('The published Steward schema is incompatible with this monitor.')).toBeInTheDocument();

    rerender(<StewardDashboard state={asLegacyStewardState(producerFixture('empty'))} />);
    expect(screen.getByText('No tasks are currently mirrored.')).toBeInTheDocument();
  });

  it('covers overview, tasks, signals, audit, and configuration navigation', () => {
    const { rerender } = render(<StewardDashboard state={asLegacyStewardState(signalMonitor())} />);

    fireEvent.click(screen.getByRole('tab', { name: /^State/, selected: false }));
    expect(screen.getByRole('heading', { name: 'Operations state' })).toBeInTheDocument();
    expect(screen.getByText('Scheduler')).toBeInTheDocument();

    fireEvent.click(screen.getByRole('tab', { name: /^Signals/ }));
    expect(screen.getByRole('heading', { level: 3, name: 'Signals' })).toBeInTheDocument();
    expect(screen.getByRole('tab', { name: /github-actions:ci/ })).toBeInTheDocument();
    expect(screen.getByText('CI is running')).toBeInTheDocument();

    rerender(<StewardDashboard state={asLegacyStewardState(producerFixture('failed'))} />);
    fireEvent.click(screen.getByRole('tab', { name: /^Audit/ }));
    expect(screen.getByRole('heading', { name: 'Audit findings' })).toBeInTheDocument();
    expect(screen.getByText('no public invariant details')).toBeInTheDocument();

    fireEvent.click(screen.getByRole('tab', { name: /^Config/ }));
    expect(screen.getByRole('heading', { level: 3, name: 'Public configuration' })).toBeInTheDocument();
    expect(screen.getByText('Integration mode')).toBeInTheDocument();
  });

  it('moves monitor tabs with keyboard navigation and keeps selection synchronized', () => {
    render(<StewardDashboard state={asLegacyStewardState(signalMonitor())} />);

    const tasks = screen.getByRole('tab', { name: /^Tasks/ });
    const state = screen.getByRole('tab', { name: /^State/ });
    tasks.focus();
    fireEvent.keyDown(tasks, { key: 'ArrowLeft' });
    expect(document.activeElement).toBe(state);
    expect(state).toHaveAttribute('aria-selected', 'true');

    fireEvent.keyDown(state, { key: 'End' });
    expect(screen.getByRole('tab', { name: /^Config/ })).toHaveAttribute('aria-selected', 'true');
  });

  it('paginates the task queue from producer-derived full task summaries', () => {
    render(<StewardDashboard state={asLegacyStewardState(taskWindow(11))} />);

    expect(screen.getByText('1-10 of 11')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Run focused checks 1' })).toBeInTheDocument();
    expect(screen.queryByRole('link', { name: 'Run focused checks 11' })).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'Next tasks page' }));
    expect(screen.getByText('11-11 of 11')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Run focused checks 11' })).toBeInTheDocument();
  });

  it('labels stale snapshots and task-detail loading/publication gaps', () => {
    vi.useFakeTimers({ now: new Date('2026-07-13T12:00:00Z') });
    const stale = asLegacyStewardState(producerFixture('stale'));
    render(<StewardFreshness state={stale} />);
    expect(screen.getAllByRole('status')[0]).toHaveTextContent('Stale');

    const { rerender } = render(
      <StewardTaskDetail detail={null} loaded={false} taskId="task-20260713115945-a1b2c3d4" />,
    );
    expect(screen.getByText('Loading task detail.')).toBeInTheDocument();
    rerender(<StewardTaskDetail detail={null} loaded taskId="task-20260713115945-a1b2c3d4" />);
    expect(screen.getByText(/has not been published yet/)).toBeInTheDocument();
  });
});

describe('Steward planner history and artifact loading', () => {
  it('loads planner history, shows redacted/truncated artifacts, and paginates', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify(plannerMonitor()))));
    render(<StewardPlannerLive />);

    expect(await screen.findByText('Page 1 of 2')).toBeInTheDocument();
    expect(screen.getByText('window truncated')).toBeInTheDocument();
    rerenderPlannerDetails();
    fireEvent.click(screen.getByRole('button', { name: 'Next planner history page' }));
    expect(await screen.findByText('Page 2 of 2')).toBeInTheDocument();
  });

  it('shows planner empty and fetch-error states', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(producerFixtureText('empty'))));
    const { unmount } = render(<StewardPlannerLive />);
    expect(await screen.findByText('No planner runs published')).toBeInTheDocument();

    unmount();
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('offline')));
    render(<StewardPlannerLive />);
    expect(await screen.findByText('Planner history unavailable')).toBeInTheDocument();
    expect(screen.getByText('offline')).toBeInTheDocument();
  });

  it('loads a complete producer fixture through the task-detail artifact helper', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(producerFixtureText('active')));
    vi.stubGlobal('fetch', fetchMock);

    await expect(loadPublicStewardTaskDetail('task-20260713115945-a1b2c3d4')).resolves.toMatchObject({
      schema_version: 3,
      repository: 'minhuw/coquic',
    });
    expect(fetchMock).toHaveBeenCalledWith('/steward/data/tasks/task-20260713115945-a1b2c3d4.json', { cache: 'no-store' });

    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('not found')));
    await expect(loadPublicStewardTaskDetail('missing')).resolves.toBeNull();
  });
});

describe('Steward diff dialog accessibility', () => {
  it('traps focus, closes on Escape, and restores the trigger focus', () => {
    render(<CodeBlock diffDisplay="unified-with-split-modal" language="diff" text="@@ -1 +1 @@\n-old\n+new\n" title="Patch" />);

    const trigger = screen.getByRole('button', { name: 'Open side-by-side diff' });
    trigger.focus();
    fireEvent.click(trigger);
    const dialog = screen.getByRole('dialog', { name: 'Patch side-by-side' });
    const close = screen.getByRole('button', { name: 'Close side-by-side diff' });
    expect(document.activeElement).toBe(close);

    fireEvent.keyDown(dialog, { key: 'Tab' });
    expect(document.activeElement).toBe(close);
    fireEvent.keyDown(dialog, { key: 'Escape' });
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(document.activeElement).toBe(trigger);
  });
});

function rerenderPlannerDetails() {
  const summaries = screen.getAllByText('Artifacts');
  fireEvent.click(summaries[0]);
  expect(screen.getByText('redacted / truncated')).toBeInTheDocument();
}

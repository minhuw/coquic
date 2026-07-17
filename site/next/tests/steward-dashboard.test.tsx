import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { StewardDashboard } from '@/components/steward/dashboard';
import { usePublicStewardState } from '@/components/steward/data';

import { asLegacyStewardState, producerFixture, producerFixtureText, signalMonitor, taskWindow } from './fixtures';

afterEach(() => {
  cleanup();
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

describe('Steward dashboard state characterization', () => {
  it('keeps every producer fixture state factual and assigns idle a neutral semantic role', () => {
    const expectedStates = [
      ['active', 'working', 'steward-dashboard-status--neutral'],
      ['blocked', 'attention', 'steward-dashboard-status--warning'],
      ['empty', 'idle', 'steward-dashboard-status--neutral'],
      ['failed', 'attention', 'steward-dashboard-status--warning'],
      ['idle', 'idle', 'steward-dashboard-status--neutral'],
      ['integration', 'working', 'steward-dashboard-status--neutral'],
      ['stale', 'idle', 'steward-dashboard-status--neutral'],
    ] as const;

    for (const [fixture, state, tone] of expectedStates) {
      const { container, unmount } = render(<StewardDashboard state={asLegacyStewardState(producerFixture(fixture))} />);
      expect(container.querySelector('[data-steward-module="dashboard"]')).toBeInTheDocument();
      const status = container.querySelector(`[data-status="${state}"]`);
      expect(status).toHaveClass(tone);
      expect(status).toHaveAttribute('data-slot', 'status-label');
      if (state === 'idle') expect(status).not.toHaveClass('steward-dashboard-status--success');
      expect(screen.getByText('minhuw/coquic')).toBeInTheDocument();
      unmount();
    }
  });

  it('reserves a complete loading shell and explains unavailable publication states', () => {
    const { container, rerender } = render(<StewardDashboard loading state={null} />);
    expect(container.querySelectorAll('[data-steward-module="dashboard"]')).toHaveLength(1);
    expect(screen.getByTestId('steward-dashboard-loading')).toBeInTheDocument();
    expect(screen.getByText('Loading the latest Steward snapshot.')).toBeInTheDocument();
    expect(screen.getByText('Offline')).toBeInTheDocument();

    rerender(<StewardDashboard fetchError="incompatible" state={null} />);
    expect(container.querySelectorAll('[data-steward-module="dashboard"]')).toHaveLength(1);
    expect(screen.getByText('The published Steward schema is incompatible with this monitor.')).toBeInTheDocument();
    rerender(<StewardDashboard fetchError="invalid" state={null} />);
    expect(container.querySelectorAll('[data-steward-module="dashboard"]')).toHaveLength(1);
    expect(screen.getByText('The published Steward snapshot is invalid and cannot be displayed.')).toBeInTheDocument();
    rerender(<StewardDashboard fetchError="unavailable" state={null} />);
    expect(container.querySelectorAll('[data-steward-module="dashboard"]')).toHaveLength(1);
    expect(screen.getByText('Steward status could not be reached; no public snapshot is available.')).toBeInTheDocument();
    rerender(<StewardDashboard state={asLegacyStewardState(producerFixture('empty'))} />);
    expect(container.querySelectorAll('[data-steward-module="dashboard"]')).toHaveLength(1);
    expect(screen.getByText('No tasks are currently mirrored.')).toBeInTheDocument();
  });

  it('reaches every view, keeps tab state exact, and retains provider navigation', () => {
    render(<StewardDashboard state={asLegacyStewardState(signalMonitor())} />);

    const expectedViews = [
      ['State', 'Operations state'],
      ['Tasks', 'Tasks'],
      ['Signals', 'Signals'],
      ['Audit', 'Audit findings'],
      ['Config', 'Public configuration'],
    ] as const;
    for (const [label, heading] of expectedViews) {
      const tab = screen.getByRole('tab', { name: new RegExp(`^${label}`) });
      fireEvent.click(tab);
      expect(tab).toHaveAttribute('aria-selected', 'true');
      expect(screen.getAllByRole('heading', { name: heading }).length).toBeGreaterThan(0);
    }

    fireEvent.change(screen.getByLabelText('View'), { target: { value: 'signals' } });
    expect(screen.getByRole('tab', { name: /^Signals/ })).toHaveAttribute('aria-selected', 'true');
    expect(screen.getByRole('tab', { name: /github-actions:ci/ })).toBeInTheDocument();
    expect(screen.getByText('CI is running')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Planner' })).toHaveAttribute('href', '/steward/planner');
  });

  it('preserves task pagination, detail links, planner navigation, and remote commit links', () => {
    const monitor = taskWindow(11);
    const firstTask = monitor.tasks[0];
    if (!firstTask) throw new Error('task window is empty');
    Object.assign(firstTask, { commit: 'abcdef123456', commit_url: 'https://github.com/minhuw/coquic/commit/abcdef123456' });
    render(<StewardDashboard state={asLegacyStewardState(monitor)} />);
    const table = taskTableQueries();

    expect(table.getByText('1-10 of 11')).toBeInTheDocument();
    expect(table.getByRole('link', { name: 'Run focused checks 1' })).toHaveAttribute('href', '/steward/tasks/task-20260713115945-a1b2c3d4');
    expect(table.getByRole('link', { name: /abcdef123456/ })).toHaveAttribute('href', 'https://github.com/minhuw/coquic/commit/abcdef123456');
    expect(table.queryByRole('link', { name: 'Run focused checks 11' })).not.toBeInTheDocument();

    fireEvent.click(table.getByRole('button', { name: 'Next tasks page' }));
    expect(table.getByText('11-11 of 11')).toBeInTheDocument();
    expect(table.getByRole('link', { name: 'Run focused checks 11' })).toBeInTheDocument();
  });

  it('retains the last valid task evidence when a refresh fails', async () => {
    vi.useFakeTimers();
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response(producerFixtureText('active')))
      .mockRejectedValueOnce(new Error('offline'));
    vi.stubGlobal('fetch', fetchMock);

    render(<LiveDashboardProbe />);
    await act(async () => {
      await Promise.resolve();
      await Promise.resolve();
      await Promise.resolve();
    });
    expect(taskTableQueries().getByRole('link', { name: 'Run focused checks' })).toBeInTheDocument();

    await act(async () => {
      await vi.advanceTimersByTimeAsync(10_000);
    });
    expect(screen.getByTestId('dashboard-refresh-result')).toHaveTextContent('unavailable:minhuw/coquic');
    expect(screen.getByText('Showing the last valid snapshot; the latest transport request failed.')).toBeInTheDocument();
    expect(taskTableQueries().getByRole('link', { name: 'Run focused checks' })).toBeInTheDocument();
  });

  it('keeps long labels and truncated windows inside named local scrolling regions', () => {
    const monitor = taskWindow(21);
    monitor.tasks_truncated = true;
    const task = monitor.tasks[0];
    if (!task) throw new Error('task window is empty');
    task.title = 'A deliberately long public task label that must remain readable without widening the route';
    render(<StewardDashboard state={asLegacyStewardState(monitor)} />);
    const table = taskTableQueries();

    expect(table.getByText('1-10 of 21')).toBeInTheDocument();
    expect(screen.getByText('Task window truncated; showing the published task window.')).toBeInTheDocument();
    expect(table.getByRole('link', { name: /deliberately long public task label/ })).toBeInTheDocument();
    expect(document.querySelector('[data-scroll-region]')).toBeInTheDocument();
  });
});

function LiveDashboardProbe() {
  const monitor = usePublicStewardState();
  return (
    <>
      <output data-testid="dashboard-refresh-result">{monitor.result.status}:{monitor.state?.repository ?? 'none'}</output>
      <StewardDashboard fetchError={monitor.error} loading={monitor.loading} state={monitor.state} />
    </>
  );
}

function taskTableQueries() {
  const table = document.querySelector<HTMLElement>('.steward-dashboard-task-table');
  if (!table) throw new Error('dashboard task table is not rendered');
  return within(table);
}

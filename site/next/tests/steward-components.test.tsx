import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  loadPublicStewardStateResult,
  loadPublicStewardTaskDetail,
  loadPublicStewardTaskDetailResult,
  StewardDashboard,
  StewardFreshness,
  StewardStatusLabel,
  StewardTaskDetail,
  stewardStatusTone,
  usePublicStewardState,
  usePublicStewardTaskDetail,
} from '@/components/steward-public';
import { CodeBlock } from '@/components/steward-code-block';
import { StewardPlannerLive } from '@/components/steward-planner';
import { publicPipelineGraph, publicTaskFlow } from '@/components/steward/task-flow';

import {
  asLegacyStewardState,
  plannerMonitor,
  producerFixture,
  producerFixtureText,
  signalMonitor,
  taskDetail,
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

describe('Steward request states', () => {
  it('renders operational states through StatusLabel with a tone and icon', () => {
    render(
      <>
        <StewardStatusLabel status="failed" />
        <StewardStatusLabel status="unknown-status" />
      </>,
    );

    const failed = screen.getByText('failed').closest('[data-slot="status-label"]');
    const unknown = screen.getByText('unknown-status').closest('[data-slot="status-label"]');
    if (!failed || !unknown) throw new Error('expected StatusLabel wrappers');
    expect(failed).toHaveAttribute('data-slot', 'status-label');
    expect(failed).toHaveAttribute('data-tone', 'danger');
    expect(failed.closest('[data-slot="badge"]')).not.toBeInTheDocument();
    expect(unknown).toHaveAttribute('data-slot', 'status-label');
    expect(unknown).toHaveAttribute('data-tone', 'neutral');
  });

  it('distinguishes dashboard publication, incompatibility, invalid data, and transport failure', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response(producerFixtureText('active')))
      .mockResolvedValueOnce(new Response(JSON.stringify({ reason: 'incompatible' }), { status: 409 }))
      .mockResolvedValueOnce(new Response('{'))
      .mockRejectedValueOnce(new Error('offline'));
    vi.stubGlobal('fetch', fetchMock);

    await expect(loadPublicStewardStateResult()).resolves.toMatchObject({
      status: 'ready',
      data: { repository: 'minhuw/coquic' },
    });
    await expect(loadPublicStewardStateResult()).resolves.toMatchObject({ status: 'incompatible', data: null });
    await expect(loadPublicStewardStateResult()).resolves.toMatchObject({ status: 'invalid', data: null });
    await expect(loadPublicStewardStateResult()).resolves.toMatchObject({ status: 'unavailable', data: null });
    expect(fetchMock).toHaveBeenCalledTimes(4);
  });

  it('distinguishes task detail publication, invalid JSON, and transport failure', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response('', { status: 404 }))
      .mockResolvedValueOnce(new Response('[]'))
      .mockRejectedValueOnce(new Error('offline'))
      .mockResolvedValueOnce(new Response(JSON.stringify(taskDetail())));
    vi.stubGlobal('fetch', fetchMock);

    await expect(loadPublicStewardTaskDetailResult('missing')).resolves.toMatchObject({ status: 'not-published', data: null });
    await expect(loadPublicStewardTaskDetailResult('invalid')).resolves.toMatchObject({ status: 'invalid', data: null });
    await expect(loadPublicStewardTaskDetailResult('offline')).resolves.toMatchObject({ status: 'unavailable', data: null });
    await expect(loadPublicStewardTaskDetailResult('task-20260713115945-a1b2c3d4')).resolves.toMatchObject({
      status: 'ready',
      data: { task: { id: 'task-20260713115945-a1b2c3d4' } },
    });
  });

  it('maps terminal outcomes to semantic tones without treating current work as success', () => {
    expect(stewardStatusTone('pushed')).toBe('success');
    expect(stewardStatusTone('attention')).toBe('warning');
    expect(stewardStatusTone('failed')).toBe('danger');
    expect(stewardStatusTone('running')).toBe('neutral');
    expect(stewardStatusTone('unknown-status')).toBe('neutral');
  });

  it('retains the last valid dashboard snapshot across a failed refresh and clears its timer', async () => {
    vi.useFakeTimers();
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response(producerFixtureText('active')))
      .mockRejectedValueOnce(new Error('offline'));
    vi.stubGlobal('fetch', fetchMock);

    const { unmount } = render(<StateProbe />);
    await act(async () => {
      await Promise.resolve();
      await Promise.resolve();
      await Promise.resolve();
    });
    expect(screen.getByTestId('state-result')).toHaveTextContent('ready:minhuw/coquic');

    await act(async () => {
      await vi.advanceTimersByTimeAsync(10_000);
    });
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(screen.getByTestId('state-result')).toHaveTextContent('unavailable:minhuw/coquic');

    unmount();
    expect(vi.getTimerCount()).toBe(0);
  });

  it('keeps the active attempt open, follows the active stage, and respects user collapse and tab selection', () => {
    vi.stubGlobal('ResizeObserver', class {
      disconnect() {}
      observe() {}
      unobserve() {}
    });
    const detail = activeTaskDetail();
    const { rerender } = render(
      <StewardTaskDetail detail={detail} loaded taskId={detail.task.id} />,
    );

    const attempt = screen.getByRole('button', { name: /Initial attempt/ });
    expect(attempt).toHaveAttribute('aria-expanded', 'true');
    expect(screen.getByRole('tab', { name: /^Review/ })).toHaveAttribute('aria-selected', 'true');

    fireEvent.click(attempt);
    expect(attempt).toHaveAttribute('aria-expanded', 'false');
    rerender(<StewardTaskDetail detail={detail} loaded taskId={detail.task.id} />);
    expect(screen.getByRole('button', { name: /Initial attempt/ })).toHaveAttribute('aria-expanded', 'false');

    fireEvent.click(attempt);
    const patch = screen.getByRole('tab', { name: /^Patch/ });
    fireEvent.click(patch);
    expect(patch).toHaveAttribute('aria-selected', 'true');

    const integrating = { ...detail, task: { ...detail.task, status: 'integrating' }, events: [
      ...detail.events,
      { task_id: detail.task.id, kind: 'integration.started', message: 'integration', created_at: '2026-07-13T12:03:00Z', data: {} },
    ] };
    rerender(<StewardTaskDetail detail={integrating} loaded taskId={detail.task.id} />);
    expect(screen.getByRole('tab', { name: /^Patch/ })).toHaveAttribute('aria-selected', 'true');
  });

  it('derives a stable pipeline with current stage and feedback loop labels', () => {
    const flow = publicTaskFlow(activeTaskDetail());
    const graph = publicPipelineGraph(flow);

    expect(flow.activeKey).toBe('review');
    expect(flow.stages.map((stage) => stage.key)).toEqual(['code', 'validation', 'review', 'integration']);
    expect(flow.loops.review).toBe(1);
    expect(graph.nodes.filter((node) => node.data.stage).map((node) => node.data.stage?.label)).toEqual([
      'Code Generation',
      'Validation',
      'Review',
      'Integration',
    ]);
    expect(graph.edges.find((edge) => edge.id === 'review-code')).toMatchObject({
      label: 'review x1',
      className: 'pipeline-edge feedback review active',
    });
  });

  it('refreshes task detail on the 30-second contract without overlapping requests', async () => {
    vi.useFakeTimers();
    const detail = taskDetail();
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify(detail)))
      .mockRejectedValueOnce(new Error('offline'));
    vi.stubGlobal('fetch', fetchMock);

    const { unmount } = render(
      <TaskProbe taskId="task-20260713115945-a1b2c3d4" detailJson="/custom/detail.json" />,
    );
    await act(async () => {
      await Promise.resolve();
      await Promise.resolve();
      await Promise.resolve();
    });
    expect(fetchMock).toHaveBeenCalledWith('/custom/detail.json', { cache: 'no-store' });
    expect(screen.getByTestId('task-result')).toHaveTextContent('ready:task-20260713115945-a1b2c3d4');

    await act(async () => {
      await vi.advanceTimersByTimeAsync(30_000);
    });
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(screen.getByTestId('task-result')).toHaveTextContent('unavailable:task-20260713115945-a1b2c3d4');

    unmount();
    expect(vi.getTimerCount()).toBe(0);
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

function StateProbe() {
  const monitor = usePublicStewardState();
  return <output data-testid="state-result">{monitor.result.status}:{monitor.state?.repository ?? 'none'}</output>;
}

function TaskProbe({ detailJson, taskId }: { detailJson: string; taskId: string }) {
  const monitor = usePublicStewardTaskDetail(taskId, detailJson);
  return <output data-testid="task-result">{monitor.result.status}:{monitor.detail?.task.id ?? 'none'}</output>;
}

function activeTaskDetail() {
  const detail = taskDetail();
  detail.task.status = 'reviewing';
  detail.events = [
    {
      task_id: detail.task.id,
      kind: 'worktree.ready',
      message: '/worktrees/task',
      created_at: '2026-07-13T12:00:00Z',
      data: { branch: detail.task.branch_name },
    },
    {
      task_id: detail.task.id,
      kind: 'worker.revision_requested',
      message: 'review requested',
      created_at: '2026-07-13T12:01:00Z',
      data: { revision: 1, review: { verdict: 'block', summary: 'needs another pass' } },
    },
    {
      task_id: detail.task.id,
      kind: 'review.finished',
      message: 'review complete',
      created_at: '2026-07-13T12:02:00Z',
      data: { review: { verdict: 'approve', summary: 'ready to integrate' } },
    },
  ];
  detail.attempts = [{
    attempt: 0,
    label: 'Initial attempt',
    started_at: '2026-07-13T12:00:00Z',
    updated_at: '2026-07-13T12:02:00Z',
    worker: {
      name: 'worker-1',
      role: 'worker',
      label: 'Worker',
      exit_code: 0,
      completed: true,
      diagnostics: {
        status: 'complete',
        summary: 'worker complete',
        exit_code: 0,
        last_message_present: true,
        event_count: 1,
        error_count: 0,
        last_event_type: 'message',
        last_item_type: 'message',
        last_item_status: 'completed',
        last_error: '',
        last_output: 'done',
        timed_out: false,
      },
      transcript: { text: 'worker transcript', size: 18, truncated: false, tail_bytes: 18 },
      last_message: null,
    },
    reviewer: null,
    review: { verdict: 'approve', summary: 'ready to integrate', findings: [], validation_gaps: [], remaining_risk: '' },
    patch: { text: '@@ -1 +1 @@\n-old\n+new\n', size: 30, truncated: false, tail_bytes: 30 },
    validations: [],
  }];
  return detail;
}

import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  StewardTaskDetail,
  usePublicStewardTaskDetail,
} from '@/components/steward-public';
import type {
  PublicStewardArtifact,
  PublicStewardAttempt,
  PublicStewardRunArtifact,
  PublicStewardTaskDetail,
} from '@/components/steward-public';
import { publicPipelineGraph, publicTaskFlow } from '@/components/steward/task-flow';

import { taskDetail } from './fixtures';

afterEach(() => {
  cleanup();
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

beforeEach(() => {
  vi.stubGlobal('ResizeObserver', class {
    disconnect() {}
    observe() {}
    unobserve() {}
  });
});

describe('Steward task request states and anatomy', () => {
  it.each([
    ['loading', false, 'Loading task detail'],
    ['not-published', true, 'Task detail is not published'],
    ['unavailable', true, 'Task detail is unavailable'],
    ['invalid', true, 'Task detail is invalid'],
    ['incompatible', true, 'Task detail schema is incompatible'],
  ] as const)('renders the typed %s state without adding a landmark', (requestStatus, loaded, heading) => {
    const { container } = render(
      <StewardTaskDetail
        detail={null}
        loaded={loaded}
        requestStatus={requestStatus}
        taskId="task-20260713115945-a1b2c3d4"
      />,
    );

    expect(screen.getByRole('heading', { name: heading, level: 1 })).toBeInTheDocument();
    expect(container.querySelectorAll('main')).toHaveLength(0);
  });

  it('renders one component shell with a sequential evidence heading structure', () => {
    vi.stubGlobal('ResizeObserver', class {
      disconnect() {}
      observe() {}
      unobserve() {}
    });
    const detail = richDetail();
    const { container } = render(<StewardTaskDetail detail={detail} loaded requestStatus="ready" taskId={detail.task.id} />);

    expect(container.querySelectorAll('main')).toHaveLength(0);
    expect(screen.getByRole('heading', { name: detail.task.title, level: 1 })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Current iteration', level: 2 })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Attempts', level: 2 })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Timeline', level: 2 })).toBeInTheDocument();
    expect(screen.getByText('Current conclusion')).toBeInTheDocument();
    expect(screen.getByText(detail.task.branch_name)).toBeInTheDocument();
    expect(screen.queryByText('Showing the last published task detail; the latest refresh is unavailable.')).not.toBeInTheDocument();
  });

  it('retains detail while a refresh reports a transport error', () => {
    const detail = richDetail();
    render(
      <StewardTaskDetail
        detail={detail}
        loaded
        requestStatus="unavailable"
        taskId={detail.task.id}
      />,
    );

    expect(screen.getByRole('heading', { name: detail.task.title, level: 1 })).toBeInTheDocument();
    expect(screen.getByRole('status')).toHaveTextContent('latest refresh is unavailable');
  });
});

describe('Steward task flow and evidence state', () => {
  it('keeps feature and non-feature stage contracts and feedback counts exact', () => {
    const feature = richDetail();
    feature.task.kind = 'feature';
    feature.task.workflow = 'feature';
    feature.task.spec.workflow = 'feature';
    feature.events = [
      event(feature.task.id, 'implementation_plan.finished', 'plan ready'),
      event(feature.task.id, 'worktree.ready', '/worktrees/task'),
      event(feature.task.id, 'worker.validation_revision_requested', 'validation revision'),
      event(feature.task.id, 'worker.revision_requested', 'review revision'),
      event(feature.task.id, 'worker.integration_revision_requested', 'integration revision'),
    ];
    const featureFlow = publicTaskFlow(feature);
    const featureGraph = publicPipelineGraph(featureFlow);

    expect(featureFlow.stages.map((stage) => stage.key)).toEqual(['plan', 'code', 'validation', 'review', 'integration']);
    expect(featureFlow.loops).toEqual({ validation: 1, review: 1, integration: 1 });
    expect(featureGraph.nodes.filter((node) => node.data.stage)).toHaveLength(5);
    expect(featureGraph.edges.find((edge) => edge.id === 'review-code')).toMatchObject({
      label: 'review x1',
      className: 'pipeline-edge feedback review active',
    });
    const reviewEdge = featureGraph.edges.find((edge) => edge.id === 'review-code');
    const reviewMarker = reviewEdge?.markerEnd;
    expect(typeof reviewMarker === 'object' && reviewMarker !== null ? reviewMarker.color : '').toContain('var(--task-flow-loop)');

    const nonFeature = richDetail();
    nonFeature.task.kind = 'fix';
    nonFeature.task.workflow = 'fix';
    nonFeature.task.spec.workflow = 'fix';
    const nonFeatureFlow = publicTaskFlow(nonFeature);
    expect(nonFeatureFlow.stages.map((stage) => stage.key)).toEqual(['code', 'validation', 'review', 'integration']);
    expect(nonFeatureFlow.stages.some((stage) => stage.key === 'plan')).toBe(false);
  });

  it.each(['queued', 'running', 'reviewing', 'integrating', 'pushed', 'failed', 'blocked'] as const)(
    'derives a textual stage state for %s',
    (status) => {
      const detail = richDetail();
      detail.task.status = status;
      const flow = publicTaskFlow(detail);
      expect(flow.stages).toHaveLength(4);
      expect(flow.stages.map((stage) => stage.label)).toEqual([
        'Code Generation',
        'Validation',
        'Review',
        'Integration',
      ]);
      expect(flow.stages.every((stage) => stage.detail.length > 0)).toBe(true);
      if (status === 'failed' || status === 'blocked') {
        expect(flow.stages.some((stage) => stage.state === 'blocked')).toBe(true);
      }
    },
  );
});

describe('Steward task attempts and artifacts', () => {
  it('keeps active-attempt auto-open, manual collapse, keyboard tabs, and manual tab override', async () => {
    const detail = richDetail();
    const { rerender } = render(<StewardTaskDetail detail={detail} loaded requestStatus="ready" taskId={detail.task.id} />);
    const attempt = screen.getByRole('button', { name: /Initial attempt/ });

    expect(attempt).toHaveAttribute('aria-expanded', 'true');
    expect(screen.getByRole('tab', { name: /^Review/ })).toHaveAttribute('aria-selected', 'true');

    fireEvent.click(attempt);
    expect(attempt).toHaveAttribute('aria-expanded', 'false');
    rerender(<StewardTaskDetail detail={detail} loaded requestStatus="ready" taskId={detail.task.id} />);
    expect(screen.getByRole('button', { name: /Initial attempt/ })).toHaveAttribute('aria-expanded', 'false');

    fireEvent.click(screen.getByRole('button', { name: /Initial attempt/ }));
    const reviewTab = screen.getByRole('tab', { name: /^Review/ });
    reviewTab.focus();
    await act(async () => {
      fireEvent.keyDown(reviewTab, { key: 'ArrowLeft' });
    });
    expect(screen.getByRole('tab', { name: /^Validation/ })).toHaveAttribute('aria-selected', 'true');
    fireEvent.click(screen.getByRole('tab', { name: /^Patch/ }));
    expect(screen.getByRole('tab', { name: /^Patch/ })).toHaveAttribute('aria-selected', 'true');

    detail.task.status = 'integrating';
    rerender(<StewardTaskDetail detail={detail} loaded requestStatus="ready" taskId={detail.task.id} />);
    expect(screen.getByRole('tab', { name: /^Patch/ })).toHaveAttribute('aria-selected', 'true');
  });

  it('follows the integration stage automatically until a tab is manually selected', () => {
    const detail = richDetail();
    detail.task.status = 'integrating';
    detail.events = [
      ...detail.events,
      event(detail.task.id, 'integration.started', 'integration started'),
    ];
    render(<StewardTaskDetail detail={detail} loaded requestStatus="ready" taskId={detail.task.id} />);

    expect(screen.getByRole('tab', { name: /^Patch/ })).toHaveAttribute('aria-selected', 'true');
    fireEvent.click(screen.getByRole('tab', { name: /^Transcript/ }));
    expect(screen.getByRole('tab', { name: /^Transcript/ })).toHaveAttribute('aria-selected', 'true');
  });

  it('shows validation pass/fail facts, review verdict, and artifact truncation metadata', () => {
    const detail = richDetail();
    detail.attempts[0]!.validations = [
      {
        index: 1,
        command: ['npm', 'run', 'typecheck'],
        passed: true,
        exit_code: 0,
        summary: 'Typecheck passed',
        iteration: 2,
        started_at: '2026-07-13T12:01:00Z',
        completed_at: '2026-07-13T12:01:05Z',
        log: artifact('typecheck passed', { truncated: true, tail_bytes: 17 }),
      },
      {
        index: 2,
        command: ['npm', 'run', 'test'],
        passed: false,
        exit_code: 1,
        summary: 'One test failed',
        iteration: 2,
        started_at: '2026-07-13T12:02:00Z',
        completed_at: '2026-07-13T12:02:05Z',
        log: null,
      },
    ];
    render(<StewardTaskDetail detail={detail} loaded requestStatus="ready" taskId={detail.task.id} />);
    fireEvent.click(screen.getByRole('tab', { name: /^Validation/ }));

    expect(screen.getAllByText('Pass')).toHaveLength(2);
    expect(screen.getAllByText('Typecheck passed')).toHaveLength(2);
    expect(screen.getAllByText('iteration 2')).toHaveLength(2);
    expect(screen.getByText(/truncated; showing tail/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: /npm run test/ }));
    expect(screen.getAllByText('Fail')).toHaveLength(2);
    expect(screen.getAllByText('One test failed')).toHaveLength(2);

    fireEvent.click(screen.getByRole('tab', { name: /^Review/ }));
    expect(screen.getAllByText('approve').length).toBeGreaterThan(0);
    expect(screen.getAllByText('Ready to integrate').length).toBeGreaterThan(0);
  });

  it('loads remote artifacts and retains factual error state when the URL fails', async () => {
    const detail = richDetail();
    detail.attempts[0]!.patch = artifact('', { url: '/artifacts/patch.diff', size: 64 });
    const fetchMock = vi.fn().mockResolvedValue(new Response('@@ -1 +1 @@\n-old\n+new\n'));
    vi.stubGlobal('fetch', fetchMock);
    render(<StewardTaskDetail detail={detail} loaded requestStatus="ready" taskId={detail.task.id} />);
    fireEvent.click(screen.getByRole('tab', { name: /^Patch/ }));
    expect(screen.getByText('Loading artifact.')).toBeInTheDocument();
    await waitFor(() => {
      const diffContainer = screen.getByLabelText('Unified diff');
      const diffTable = within(diffContainer).getByRole('table', { name: 'Unified diff contents' });
      expect(diffTable).toHaveTextContent('-old');
      expect(diffTable).toHaveTextContent('+new');
    });
    expect(fetchMock).toHaveBeenCalledWith('/artifacts/patch.diff', { cache: 'no-store' });

    const failure = richDetail();
    cleanup();
    failure.attempts[0]!.patch = artifact('', { url: '/artifacts/missing.diff', size: 80 });
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('offline')));
    render(<StewardTaskDetail detail={failure} loaded requestStatus="ready" taskId={failure.task.id} />);
    fireEvent.click(screen.getByRole('tab', { name: /^Patch/ }));
    await waitFor(() => expect(screen.getByText('Unable to load artifact: offline')).toBeInTheDocument());
    expect(screen.getByText('80 bytes')).toBeInTheDocument();
  });
});

describe('Steward task refresh and timeline contracts', () => {
  it('uses the exact detail URL and refreshes once after 30 seconds', async () => {
    vi.useFakeTimers();
    const detail = richDetail();
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify(detail)))
      .mockRejectedValueOnce(new Error('offline'));
    vi.stubGlobal('fetch', fetchMock);

    render(<TaskProbe taskId={detail.task.id} />);
    await act(async () => {
      await Promise.resolve();
      await Promise.resolve();
      await Promise.resolve();
    });
    expect(fetchMock).toHaveBeenCalledWith(`/steward/data/tasks/${detail.task.id}.json`, { cache: 'no-store' });

    await act(async () => {
      await vi.advanceTimersByTimeAsync(30_000);
    });
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('keeps newest-first event order and long path text intact', () => {
    const detail = richDetail();
    detail.events = [
      event(detail.task.id, 'task.created', 'first event'),
      event(detail.task.id, 'patch.saved', '/very/long/path/to/a/task/worktree/with/a/patch/file.diff'),
    ];
    render(<StewardTaskDetail detail={detail} loaded requestStatus="ready" taskId={detail.task.id} />);

    const items = screen.getAllByRole('listitem');
    const eventItems = items.filter((item) => item.id.startsWith('task-event-'));
    expect(eventItems[0]).toHaveTextContent('Patch saved');
    expect(eventItems[1]).toHaveTextContent('Task created');
    expect(screen.getByText('/very/long/path/to/a/task/worktree/with/a/patch/file.diff')).toBeInTheDocument();
    expect(screen.getByRole('list', { name: 'Task timeline, newest first' })).toHaveAttribute('tabindex', '0');
  });
});

function TaskProbe({ taskId }: { taskId: string }) {
  const result = usePublicStewardTaskDetail(taskId);
  return <output data-testid="task-refresh-result">{result.result.status}:{result.detail?.task.id ?? 'none'}</output>;
}

function richDetail(): PublicStewardTaskDetail {
  const detail = taskDetail();
  detail.task.status = 'reviewing';
  detail.events = [
    event(detail.task.id, 'worktree.ready', '/worktrees/task'),
    event(detail.task.id, 'worker.revision_requested', 'review requested', {
      revision: 1,
      review: { verdict: 'block', summary: 'Needs another pass' },
    }),
    event(detail.task.id, 'review.finished', 'review complete', {
      review: { verdict: 'approve', summary: 'Ready to integrate', findings: [], validation_gaps: [], remaining_risk: '' },
    }),
  ];
  detail.attempts = [richAttempt()];
  detail.validations = detail.attempts[0]!.validations;
  return detail;
}

function richAttempt(): PublicStewardAttempt {
  return {
    attempt: 0,
    label: 'Initial attempt',
    started_at: '2026-07-13T12:00:00Z',
    updated_at: '2026-07-13T12:03:00Z',
    worker: runArtifact('worker-0', artifact('worker transcript')),
    reviewer: runArtifact('review-0', artifact('reviewer transcript')),
    review: {
      command: 'npm run test',
      created_at: '2026-07-13T12:02:00Z',
      event_kind: 'review.finished',
      exit_code: 0,
      findings: [],
      remaining_risk: '',
      summary: 'Ready to integrate',
      validation_gaps: [],
      verdict: 'approve',
    },
    patch: artifact('@@ -1 +1 @@\n-old\n+new\n'),
    validations: [{
      index: 0,
      command: ['npm', 'run', 'test'],
      passed: true,
      exit_code: 0,
      summary: 'Task tests passed',
      iteration: 1,
      started_at: '2026-07-13T12:01:00Z',
      completed_at: '2026-07-13T12:01:05Z',
      log: artifact('all task tests passed'),
    }],
  };
}

function runArtifact(name: string, transcript: PublicStewardArtifact): NonNullable<PublicStewardRunArtifact> {
  return {
    name,
    role: 'worker',
    label: name,
    exit_code: 0,
    completed: true,
    model: 'test-model',
    reasoning_effort: 'standard',
    diagnostics: {
      status: 'ok',
      summary: 'completed',
      exit_code: 0,
      last_message_present: true,
      event_count: 1,
      error_count: 0,
      last_event_type: 'item.completed',
      last_item_type: 'message',
      last_item_status: 'completed',
      last_error: '',
      last_output: '',
      timed_out: false,
    },
    transcript,
    last_message: null,
  };
}

function artifact(text: string, overrides: Partial<NonNullable<PublicStewardArtifact>> = {}): NonNullable<PublicStewardArtifact> {
  return {
    text,
    size: text.length,
    truncated: false,
    tail_bytes: 0,
    mode: 'raw',
    ...overrides,
  };
}

function event(taskId: string, kind: string, message: string, data: Record<string, unknown> = {}) {
  return {
    task_id: taskId,
    kind,
    message,
    created_at: '2026-07-13T12:00:00Z',
    data,
  };
}

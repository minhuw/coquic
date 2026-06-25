"use client";

import '@xyflow/react/dist/style.css';

import Link from 'next/link';
import {
  Background,
  Handle,
  MarkerType,
  Position,
  ReactFlow,
  type Edge,
  type Node,
  type NodeProps,
  type SmoothStepPathOptions,
} from '@xyflow/react';
import { Activity, AlertTriangle, ArrowLeft, CheckCircle2, ChevronLeft, ChevronRight, Circle, ExternalLink, FileText, GitBranch, Inbox, ListChecks, RadioTower, Route, XCircle } from 'lucide-react';
import { type ReactNode, useEffect, useState } from 'react';

import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { CodeBlock } from '@/components/steward-code-block';
import { TranscriptView } from '@/components/steward-transcript';
import type { PublicCodexRunDiagnostics } from '@/components/steward-transcript';

export type PublicStewardTask = {
  id: string;
  title: string;
  kind: string;
  worker: string;
  priority: string;
  risk: string;
  status: string;
  summary: string;
  source: string;
  created_at: string;
  updated_at: string;
  detail_url?: string;
  detail_json?: string;
  validations: Array<{
    passed: boolean;
    exit_code: number;
    summary: string;
    iteration: number | null;
    started_at: string;
    completed_at: string;
  }>;
};

export type PublicStewardArtifact = {
  text: string;
  size: number;
  truncated: boolean;
  tail_bytes: number;
  mode?: 'redacted' | 'raw' | string;
  url?: string;
  sha256?: string;
} | null;

export type PublicStewardRunArtifact = {
  name: string;
  role: string;
  label: string;
  exit_code: number | null;
  completed: boolean | null;
  diagnostics: {
    status: string;
    summary: string;
    exit_code: number | null;
    last_message_present: boolean;
    event_count: number;
    error_count: number;
    last_event_type: string;
    last_item_type: string;
    last_item_status: string;
    last_error: string;
    last_output: string;
    timed_out: boolean;
  };
  transcript: PublicStewardArtifact;
  last_message: PublicStewardArtifact;
} | null;

export type PublicStewardValidationDetail = {
  index: number;
  command: string[];
  passed: boolean;
  exit_code: number;
  summary: string;
  iteration: number | null;
  started_at: string;
  completed_at: string;
  log: PublicStewardArtifact;
};

export type PublicStewardAttempt = {
  attempt: number;
  label: string;
  started_at?: string;
  updated_at?: string;
  worker: PublicStewardRunArtifact;
  reviewer: PublicStewardRunArtifact;
  review: Record<string, unknown> | null;
  patch: PublicStewardArtifact;
  validations: PublicStewardValidationDetail[];
};

export type PublicStewardEvent = {
  task_id: string;
  kind: string;
  message: string;
  created_at: string;
  data: Record<string, unknown>;
};

export type PublicStewardTaskDetail = {
  schema_version: number;
  generated_at: string;
  repository: string;
  main_branch: string;
  task: PublicStewardTask & {
    branch_name: string;
    spec: {
      id: string;
      kind: string;
      worker: string;
      title: string;
      prompt: string;
      priority: string;
      risk: string;
      source: string;
      allow_main_write: boolean;
      metadata: Record<string, unknown>;
    };
    has_patch: boolean;
    has_transcript: boolean;
    has_last_message: boolean;
  };
  source_task: PublicStewardTaskDetail['task'] | null;
  events: PublicStewardEvent[];
  source_events: PublicStewardEvent[];
  attempts: PublicStewardAttempt[];
  validations: PublicStewardValidationDetail[];
  artifacts: {
    patch: PublicStewardArtifact;
    transcript: PublicStewardArtifact;
    last_message: PublicStewardArtifact;
  };
  integration: {
    is_integration_task: boolean;
    source_task_id: string | null;
    runs: Array<{
      task: PublicStewardTask;
      remote: { commit: string | null; commit_url: string | null };
      commit_message: { transcript: PublicStewardArtifact; last_message: PublicStewardArtifact } | null;
      push_log: PublicStewardArtifact;
    }>;
  };
  remote: { commit: string | null; commit_url: string | null };
};

export type PublicStewardSignalItem = {
  id: string;
  provider: string;
  kind: string;
  title: string;
  summary: string;
  severity: string | null;
  status: string;
  created_at: string;
  updated_at: string;
  planned_at: string | null;
  planned_task_id: string | null;
  links: Array<{ label: string; url: string }>;
};

export type PublicStewardFetch = {
  id: string;
  provider: string;
  status: 'ok' | 'error';
  started_at: string;
  completed_at: string;
  item_count: number;
  new_item_count: number;
  has_more: boolean;
  summary: string;
  error: string | null;
};

export type PublicStewardProvider = {
  provider: string;
  poll_interval_minutes: number;
  error_retry_minutes: number;
  idle_poll_interval_minutes: number;
  suppression_hours: number;
  max_items: number;
  last_fetch_at: string | null;
  last_status: 'ok' | 'error' | null;
  last_error: string | null;
  next_due_at: string;
  idle_next_due_at?: string | null;
  due: boolean;
  idle_due?: boolean;
};

export type PublicStewardWakeup = {
  id: string;
  reason: string;
  status: string;
  created_at: string;
  consumed_at: string | null;
  data: Record<string, unknown>;
};

export type PublicStewardState = {
  schema_version: number;
  generated_at: string;
  repository: string;
  main_branch: string;
  state: 'working' | 'queued' | 'attention' | 'idle';
  counts: {
    tasks: number;
    active: number;
    queued: number;
    attention: number;
    completed: number;
    signals: number;
    pending_signals: number;
  };
  audit: string[];
  configuration: {
    repository: string;
    main_branch: string;
    integration_mode: string;
    local_only: boolean;
    enabled_signals: string[];
    scheduler_wait_interval_sec: number;
    limits: Record<string, number | null>;
    signal_providers: Record<string, {
      poll_interval_minutes: number;
      error_retry_minutes: number;
      idle_poll_interval_minutes: number;
      suppression_hours: number;
      max_items: number;
    }>;
  };
  tasks: PublicStewardTask[];
  signals: {
    schema_version: number;
    repository: string;
    enabled_signals: string[];
    generated_at: string;
    summary: string;
    items: PublicStewardSignalItem[];
    fetches: PublicStewardFetch[];
  };
  scheduler: {
    source_active: number;
    source_capacity: number;
    source_queued: number;
    integration_active: number;
    integration_queued: number;
    pending_wakeups: PublicStewardWakeup[];
    recent_wakeups: PublicStewardWakeup[];
    providers: PublicStewardProvider[];
  };
  integration: {
    active: PublicStewardTask[];
    queue: PublicStewardTask[];
    commits: Array<{
      task_id: string;
      title: string;
      status: string;
      summary: string;
      commit: string;
      commit_url: string;
      updated_at: string;
    }>;
  };
};

type StewardMirrorTab = 'overview' | 'tasks' | 'signals';
const TASK_GRAPH_LANES: Array<{
  empty: string;
  key: string;
  label: string;
  statuses: string[];
}> = [
  { key: 'queued', label: 'Queued', statuses: ['queued'], empty: 'No queued tasks' },
  { key: 'active', label: 'In Progress', statuses: ['running', 'reviewing', 'integrating'], empty: 'No active work' },
  { key: 'attention', label: 'Needs Attention', statuses: ['blocked', 'failed', 'cancelled'], empty: 'No blocked, failed, or cancelled tasks' },
  { key: 'completed', label: 'Completed', statuses: ['succeeded', 'pushed', 'no_changes'], empty: 'No completed tasks' },
];

type PublicTaskStageKey = 'code' | 'validation' | 'review' | 'integration';
type PublicTaskStageState = 'pending' | 'active' | 'complete' | 'blocked';
type PublicAttemptTab = 'transcript' | 'patch' | 'validation' | 'review';
type PublicTaskStage = {
  detail: string;
  key: PublicTaskStageKey;
  label: string;
  state: PublicTaskStageState;
};
type PublicTaskFlow = {
  activeKey: PublicTaskStageKey;
  loops: Record<'integration' | 'review' | 'validation', number>;
  stages: PublicTaskStage[];
};
type PublicPipelineNodeData = {
  stage?: PublicTaskStage;
};
type PublicPipelineNode = Node<PublicPipelineNodeData, 'pipeline'>;
type PublicPipelineEdge = Edge<Record<string, never>, 'smoothstep'> & {
  pathOptions?: SmoothStepPathOptions;
};
type PublicTimelineTone = 'neutral' | 'success' | 'danger' | 'review' | 'created';
type PublicTimelineField = {
  label: string;
  value: string;
  kind?: 'path' | 'text';
};
type PublicTimelineChip = {
  label: string;
  value: string;
  tone?: PublicTimelineTone;
};
type PublicReviewShape = {
  verdict: string;
  summary: string;
  findings: Record<string, unknown>[];
  validation_gaps: string[];
  remaining_risk: string;
};
type PublicTimelineModel = {
  title: string;
  description: string;
  tone: PublicTimelineTone;
  chips: PublicTimelineChip[];
  fields: PublicTimelineField[];
  review: PublicReviewShape | null;
};
type PublicReviewFinding = {
  detail: string;
  file: string;
  line: number | null;
  recommendation: string;
  severity: string;
  title: string;
};
type PublicReviewRecord = {
  attempt: number;
  command: string;
  created_at: string;
  event_kind: string;
  exit_code: number | null;
  findings: PublicReviewFinding[];
  remaining_risk: string;
  summary: string;
  validation_gaps: string[];
  verdict: string;
};

const STEWARD_MIRROR_TAB_COPY: Record<StewardMirrorTab, { description: string; eyebrow: string; title: string }> = {
  overview: {
    description: 'Scheduler capacity, integration queue, and recent pushes.',
    eyebrow: 'Read-only mirror',
    title: 'Operations state',
  },
  tasks: {
    description: 'Public snapshot of Steward task lanes.',
    eyebrow: 'Task graph',
    title: 'Tasks',
  },
  signals: {
    description: 'Provider schedule, current signal items, and recent fetches.',
    eyebrow: 'Signal inbox',
    title: 'Signals',
  },
};

export async function loadPublicStewardState(): Promise<PublicStewardState | null> {
  try {
    const response = await fetch('/steward/status.json', {
      cache: 'no-store',
    });
    if (!response.ok) return null;
    return response.json() as Promise<PublicStewardState>;
  } catch {
    return null;
  }
}

export async function loadPublicStewardTaskDetail(taskId: string, detailJson?: string): Promise<PublicStewardTaskDetail | null> {
  try {
    const response = await fetch(detailJson ?? publicTaskDetailJsonPath(taskId), {
      cache: 'no-store',
    });
    if (!response.ok) return null;
    return response.json() as Promise<PublicStewardTaskDetail>;
  } catch {
    return null;
  }
}

export function StewardSnapshotCardLive() {
  const state = usePublicStewardState();
  return <StewardSnapshotCard state={state} />;
}

export function StewardDashboardLive() {
  const state = usePublicStewardState();
  return (
    <div className="grid gap-4 steward-public-live">
      <StewardDashboard state={state} />
    </div>
  );
}

export function StewardTaskDetailLive({ taskId }: { taskId: string }) {
  const state = usePublicStewardState();
  const task = state?.tasks.find((item) => item.id === taskId) ?? null;
  const { detail, loaded } = usePublicStewardTaskDetail(taskId, task?.detail_json);
  return <StewardTaskDetail detail={detail} loaded={loaded} taskId={taskId} />;
}

function usePublicStewardState() {
  const [state, setState] = useState<PublicStewardState | null>(null);
  useEffect(() => {
    let cancelled = false;
    async function refresh() {
      const next = await loadPublicStewardState();
      if (!cancelled) setState(next);
    }
    void refresh();
    const timer = window.setInterval(() => void refresh(), 30_000);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, []);
  return state;
}

function usePublicStewardTaskDetail(taskId: string, detailJson?: string) {
  const [detail, setDetail] = useState<PublicStewardTaskDetail | null>(null);
  const [loaded, setLoaded] = useState(false);
  useEffect(() => {
    let cancelled = false;
    async function refresh() {
      const next = await loadPublicStewardTaskDetail(taskId, detailJson);
      if (!cancelled) {
        setDetail(next);
        setLoaded(true);
      }
    }
    setLoaded(false);
    void refresh();
    const timer = window.setInterval(() => void refresh(), 30_000);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [detailJson, taskId]);
  return { detail, loaded };
}

export function StewardSnapshotCard({ state }: { state: PublicStewardState | null }) {
  const updated = state ? relativeTime(state.generated_at) : 'not published';
  const activeTask = state?.tasks.find((task) => !isPublicIntegrationTask(task) && ['running', 'reviewing', 'integrating'].includes(task.status));
  const counts = state ? publicTaskCounts(state.tasks) : null;
  return (
    <Card className="steward-card">
      <CardHeader className="panel-head">
        <div>
          <CardTitle>Steward</CardTitle>
          <p>Autonomous maintenance mirror</p>
        </div>
        <StatusBadge status={state?.state ?? 'idle'} />
      </CardHeader>
      <CardContent className="grid gap-4">
        {state ? (
          <>
            <div className="grid gap-2 sm:grid-cols-4">
              <Metric label="Active" value={counts?.active ?? 0} />
              <Metric label="Queued" value={counts?.queued ?? 0} />
              <Metric label="Signals" value={state.counts.pending_signals} />
              <Metric label="Completed" value={counts?.completed ?? 0} />
            </div>
            <div className="rounded-[var(--radius)] border border-[var(--line)] bg-[var(--surface-2)] p-3">
              <div className="flex items-center justify-between gap-3">
                <span className="font-mono text-[11px] font-semibold uppercase text-[var(--muted)]">Current task</span>
                <span className="font-mono text-[11px] text-[var(--muted)]">{updated}</span>
              </div>
              <p className="mt-2 text-sm font-medium text-[var(--ink)]">{activeTask?.title ?? 'No active task'}</p>
              {activeTask && (
                <p className="mt-1 font-mono text-xs text-[var(--muted)]">
                  {activeTask.kind} / {activeTask.worker}
                </p>
              )}
            </div>
            <Link className="button-like w-fit" href="/steward">
              Open Steward mirror
            </Link>
          </>
        ) : (
          <div className="rounded-[var(--radius)] border border-[var(--line)] bg-[var(--surface-2)] p-3 text-sm text-[var(--muted)]">
            Waiting for Steward to publish its first public snapshot.
          </div>
        )}
      </CardContent>
    </Card>
  );
}

export function StewardDashboard({ state }: { state: PublicStewardState | null }) {
  const [activeTab, setActiveTab] = useState<StewardMirrorTab>('tasks');
  if (!state) {
    return (
      <div className="steward-mirror-shell">
        <Card className="mt-5">
          <CardContent className="p-6 text-sm text-[var(--muted)]">
          Steward has not published a public snapshot yet.
          </CardContent>
        </Card>
      </div>
    );
  }
  const counts = publicTaskCounts(state.tasks);
  const activeTask = state.tasks.find((task) => !isPublicIntegrationTask(task) && ['running', 'reviewing', 'integrating'].includes(task.status));
  const tabCopy = STEWARD_MIRROR_TAB_COPY[activeTab];
  return (
    <div className="steward-mirror-shell">
      <aside className="steward-mirror-sidebar" aria-label="Steward public mirror summary">
        <div className="steward-mirror-brand">
          <span className="brand-mark">CS</span>
          <div>
            <div className="brand-title">
              <h2>CoQUIC Steward</h2>
              <span className={`stream-dot ${state.state === 'working' ? 'live' : ''}`} aria-label={`Mirror state ${state.state}`} title={`Mirror state ${state.state}`} />
            </div>
            <p>{state.repository} / {state.main_branch}</p>
          </div>
        </div>
        <nav className="steward-mirror-nav" aria-label="Steward mirror sections" role="tablist">
          <MirrorNavItem active={activeTab === 'overview'} icon={<Activity />} label="State" onSelect={() => setActiveTab('overview')} tab="overview" value={state.state} />
          <MirrorNavItem active={activeTab === 'tasks'} icon={<ListChecks />} label="Tasks" onSelect={() => setActiveTab('tasks')} tab="tasks" value={String(counts.tasks)} />
          <MirrorNavItem active={activeTab === 'signals'} icon={<Inbox />} label="Signals" onSelect={() => setActiveTab('signals')} tab="signals" value={String(state.counts.signals)} />
        </nav>
      </aside>

      <div className="steward-mirror-main">
        <header className="steward-mirror-topbar">
          <div>
            <span className="eyebrow">{tabCopy.eyebrow}</span>
            <h2>{tabCopy.title}</h2>
            <p>{activeTab === 'overview' ? (activeTask ? activeTask.title : 'No active task in the public snapshot') : tabCopy.description}</p>
          </div>
          <div className="steward-mirror-kpis" aria-label="Steward totals">
            <Metric label="Updated" value={relativeTime(state.generated_at)} />
            <Metric label="Pending" value={state.counts.pending_signals} />
          </div>
        </header>

        <div
          aria-labelledby={`steward-tab-${activeTab}`}
          className="steward-tab-panel"
          id={`steward-panel-${activeTab}`}
          role="tabpanel"
        >
          {activeTab === 'overview' && <StewardOverviewTab state={state} />}
          {activeTab === 'tasks' && <StewardTasksTab state={state} />}
          {activeTab === 'signals' && <StewardSignalsTab state={state} />}
        </div>
    </div>
    </div>
  );
}

function StewardOverviewTab({ state }: { state: PublicStewardState }) {
  const integrationTasks = state.tasks.filter(isPublicIntegrationTask);
  return (
    <section className="steward-mirror-grid">
      <section className="steward-panel">
        <PanelTitle title="Scheduler" description="Serialized capacity and queue state" />
        <div className="steward-scheduler-lanes">
          <SchedulerLane
            active={state.scheduler.source_active}
            capacity={state.scheduler.source_capacity}
            icon={<ListChecks />}
            label="Source"
            queued={state.scheduler.source_queued}
          />
          <SchedulerLane
            active={state.scheduler.integration_active}
            capacity={1}
            icon={<GitBranch />}
            label="Integration"
            queued={state.scheduler.integration_queued}
          />
        </div>
        <div className="grid gap-2 md:grid-cols-2">
          <Fact label="Pending wakeups" value={String(state.scheduler.pending_wakeups.length)} />
          <Fact label="Recent wakeups" value={String(state.scheduler.recent_wakeups.length)} />
        </div>
      </section>

      <section className="steward-panel">
        <PanelTitle title="Integration" description="Recent integration runs and pushes to main" />
        <div className="grid gap-2">
          {state.integration.commits.length ? (
            state.integration.commits.slice(0, 5).map((commit) => (
              <a className="steward-row" href={commit.commit_url} key={commit.commit} rel="noreferrer" target="_blank">
                <GitBranch className="size-4" />
                <span>
                  <b>{commit.title}</b>
                  <small>{shortSha(commit.commit)} / {relativeTime(commit.updated_at)}</small>
                </span>
                <StatusBadge status={commit.status} />
              </a>
            ))
          ) : integrationTasks.length ? (
            integrationTasks.slice(0, 8).map((task) => (
              <Link className="steward-row" href={task.detail_url ?? `/steward/tasks/${task.id}`} key={task.id}>
                <GitBranch className="size-4" />
                <span>
                  <b>{integrationTaskTitle(task)}</b>
                  <small>{task.status} / {relativeTime(task.updated_at)}</small>
                </span>
                <StatusBadge status={task.status} />
              </Link>
            ))
          ) : (
            <div className="steward-empty">No Integration runs in the mirror window</div>
          )}
        </div>
      </section>
    </section>
  );
}

function StewardTasksTab({ state }: { state: PublicStewardState }) {
  const userTasks = state.tasks.filter((task) => !isPublicIntegrationTask(task));
  return (
    <div className="steward-task-panels">
      <section className="panel">
        <PanelTitle icon={<Route size={17} />} title="Task Graph" />
        <PublicTaskGraph tasks={userTasks} />
      </section>
      <section className="panel">
        <PanelTitle icon={<ListChecks size={17} />} title="Task Queue" />
        <PublicTaskTable repository={state.repository} tasks={userTasks} />
      </section>
    </div>
  );
}

function PublicTaskTable({ repository, tasks }: { repository: string; tasks: PublicStewardTask[] }) {
  const pagination = usePublicPagination(tasks);
  if (!tasks.length) return <div className="empty-state">No tasks are currently mirrored.</div>;
  return (
    <>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Task</th>
              <th>Status</th>
              <th>Kind</th>
              <th>Priority</th>
              <th>Risk</th>
              <th>Updated</th>
              <th>Remote</th>
            </tr>
          </thead>
          <tbody>
            {pagination.pageItems.map((task, index) => {
              const remote = taskRemote(task, repository);
              return (
                <tr className={pagination.start + index === 0 ? 'selected-row' : ''} key={task.id}>
                  <td>
                    <Link className="link-button" href={task.detail_url ?? `/steward/tasks/${task.id}`}>
                      {task.title}
                    </Link>
                  </td>
                  <td><StatusPill status={task.status} /></td>
                  <td><TaskSpecChip value={task.kind} /></td>
                  <td><TaskSpecChip tone={`priority-${task.priority}`} value={task.priority} /></td>
                  <td><TaskSpecChip tone={`risk-${task.risk}`} value={task.risk} /></td>
                  <td>
                    <time className="compact-time mono" dateTime={task.updated_at} title={shortDate(task.updated_at)}>
                      {compactDate(task.updated_at)}
                    </time>
                  </td>
                  <td>{remote ? <CommitLink remote={remote} /> : <span className="muted">-</span>}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      <PaginationControls
        itemLabel="tasks"
        onPageChange={pagination.setPage}
        page={pagination.page}
        pageCount={pagination.pageCount}
        pageSize={pagination.pageSize}
        total={tasks.length}
      />
    </>
  );
}

function PublicTaskGraph({ tasks }: { tasks: PublicStewardTask[] }) {
  return (
    <div className="graph">
      {TASK_GRAPH_LANES.map((lane) => {
        const laneTasks = tasks
          .filter((task) => lane.statuses.includes(task.status))
          .sort((left, right) => taskUpdatedAtMs(right) - taskUpdatedAtMs(left));
        return (
          <div className={`graph-lane lane-${lane.key}`} key={lane.key}>
            <div className="lane-title">
              <span>{lane.label}</span>
              <b>{laneTasks.length}</b>
            </div>
            <div className="lane-items">
              {laneTasks.map((task, index) => (
                <Link
                  className={`graph-node ${index === 0 && lane.key === 'completed' ? 'active' : ''}`}
                  href={task.detail_url ?? `/steward/tasks/${task.id}`}
                  key={task.id}
                  title={task.title}
                >
                  <div className="graph-node-top">
                    <StatusPill status={task.status} />
                    <time className="graph-node-time mono" dateTime={task.updated_at} title={shortDate(task.updated_at)}>
                      Updated {compactDate(task.updated_at)}
                    </time>
                  </div>
                  <div className="graph-node-title">
                    <b>{task.title}</b>
                  </div>
                  <div className="graph-node-context">
                    <span>Agent</span>
                    <b>{task.worker}</b>
                  </div>
                  <div className="graph-node-meta">
                    <TaskSpecChip label="Type" value={task.kind} />
                    <TaskSpecChip label="Priority" tone={`priority-${task.priority}`} value={task.priority} />
                    <TaskSpecChip label="Risk" tone={`risk-${task.risk}`} value={task.risk} />
                  </div>
                </Link>
              ))}
              {!laneTasks.length && <div className="lane-empty">{lane.empty}</div>}
            </div>
          </div>
        );
      })}
    </div>
  );
}

function taskUpdatedAtMs(task: PublicStewardTask) {
  const value = Date.parse(task.updated_at);
  return Number.isFinite(value) ? value : 0;
}

function TaskSpecChip({ label, tone = '', value }: { label?: string; tone?: string; value: string }) {
  return (
    <span className={`task-spec-chip ${tone}`}>
      {label && <b>{label}</b>}
      <span>{value || '-'}</span>
    </span>
  );
}

function CommitLink({ remote }: { remote: { commit: string; url: string } }) {
  return (
    <a className="commit-link" href={remote.url} rel="noreferrer" target="_blank">
      <ExternalLink size={14} />
      <span className="mono">{shortSha(remote.commit)}</span>
    </a>
  );
}

function taskRemote(task: PublicStewardTask, repository: string): { commit: string; url: string } | null {
  const summaryMatch = task.summary.match(/\b(?:pushed|commit)\s+([a-f0-9]{7,40})\b/i);
  const rawTask = task as unknown as Record<string, unknown>;
  const metadataCommit = typeof rawTask.commit === 'string' ? rawTask.commit : '';
  const metadataUrl = typeof rawTask.commit_url === 'string' ? rawTask.commit_url : '';
  const commit = metadataCommit || summaryMatch?.[1] || '';
  if (!commit) return null;
  return {
    commit,
    url: metadataUrl || `https://github.com/${repository}/commit/${commit}`,
  };
}

function PaginationControls({
  itemLabel,
  onPageChange,
  page,
  pageCount,
  pageSize,
  total,
}: {
  itemLabel: string;
  onPageChange: (page: number) => void;
  page: number;
  pageCount: number;
  pageSize: number;
  total: number;
}) {
  if (total <= pageSize) return null;
  const start = total ? (page - 1) * pageSize + 1 : 0;
  const end = Math.min(page * pageSize, total);
  return (
    <nav className="pagination-bar" aria-label={`${itemLabel} pagination`}>
      <span className="pagination-range">{start}-{end} of {total}</span>
      <div className="pagination-actions">
        <button
          aria-label={`Previous ${itemLabel} page`}
          className="secondary"
          disabled={page <= 1}
          onClick={() => onPageChange(page - 1)}
          title="Previous page"
          type="button"
        >
          <ChevronLeft size={14} />
        </button>
        <PaginationJump itemLabel={itemLabel} onPageChange={onPageChange} page={page} pageCount={pageCount} />
        <button
          aria-label={`Next ${itemLabel} page`}
          className="secondary"
          disabled={page >= pageCount}
          onClick={() => onPageChange(page + 1)}
          title="Next page"
          type="button"
        >
          <ChevronRight size={14} />
        </button>
      </div>
    </nav>
  );
}

function PaginationJump({
  itemLabel,
  onPageChange,
  page,
  pageCount,
}: {
  itemLabel: string;
  onPageChange: (page: number) => void;
  page: number;
  pageCount: number;
}) {
  const [draft, setDraft] = useState({ page, value: String(page) });
  const draftPage = draft.page === page ? draft.value : String(page);

  function submitPage() {
    const parsed = Number.parseInt(draftPage, 10);
    if (Number.isNaN(parsed)) {
      setDraft({ page, value: String(page) });
      return;
    }
    const nextPage = Math.max(1, Math.min(parsed, pageCount));
    setDraft({ page: nextPage, value: String(nextPage) });
    if (nextPage !== page) onPageChange(nextPage);
  }
  return (
    <form
      className="pagination-jump"
      onSubmit={(event) => {
        event.preventDefault();
        submitPage();
      }}
    >
      <span>Page</span>
      <input
        aria-label={`Go to ${itemLabel} page`}
        className="mono"
        inputMode="numeric"
        max={pageCount}
        min={1}
        onBlur={submitPage}
        onChange={(event) => setDraft({ page, value: event.target.value })}
        pattern="[0-9]*"
        type="number"
        value={draftPage}
      />
      <span>/ {pageCount}</span>
    </form>
  );
}

function usePublicPagination<T>(items: T[], pageSize = 10) {
  const [page, setPage] = useState(1);
  const pageCount = Math.max(1, Math.ceil(items.length / pageSize));
  const safePage = Math.min(page, pageCount);
  const start = (safePage - 1) * pageSize;
  const pageItems = items.slice(start, start + pageSize);
  useEffect(() => {
    if (page !== safePage) setPage(safePage);
  }, [page, safePage]);
  return {
    page: safePage,
    pageCount,
    pageItems,
    pageSize,
    setPage,
    start,
  };
}

function StewardSignalsTab({ state }: { state: PublicStewardState }) {
  const [selectedProvider, setSelectedProvider] = useState<string | null>(null);
  const fallbackProvider = state.scheduler.providers[0]?.provider ?? state.signals.items[0]?.provider ?? state.signals.fetches[0]?.provider ?? null;
  const providerNames = new Set(state.scheduler.providers.map((provider) => provider.provider));
  const activeProvider = selectedProvider && providerNames.has(selectedProvider) ? selectedProvider : fallbackProvider;
  const activeProviderMeta = state.scheduler.providers.find((provider) => provider.provider === activeProvider) ?? null;
  const signalItems = activeProvider
    ? state.signals.items.filter((item) => item.provider === activeProvider)
    : state.signals.items;
  const recentFetches = (activeProvider
    ? state.signals.fetches.filter((fetch) => fetch.provider === activeProvider)
    : state.signals.fetches
  ).slice(0, 8);
  return (
    <section className="steward-panel steward-signals-panel">
      <PanelTitle title="Signals" description="Select a provider to inspect its signal inbox and fetch history" />
      <div className="steward-signals-layout">
        <div className="steward-provider-tabs" role="tablist" aria-label="Signal providers">
          <SignalColumnHeader title="Providers" description="Poll cadence and provider health" />
          {state.scheduler.providers.map((provider) => (
            <ProviderTab
              active={provider.provider === activeProvider}
              key={provider.provider}
              onSelect={() => setSelectedProvider(provider.provider)}
              provider={provider}
            />
          ))}
          {!state.scheduler.providers.length && <div className="steward-empty">No signal providers</div>}
        </div>

        <div className="steward-provider-detail">
          <div className="steward-provider-detail-head">
            <div>
              <b>{activeProvider ?? 'No provider selected'}</b>
              <span>{activeProviderMeta ? providerScheduleLabel(activeProviderMeta) : 'Waiting for provider state'}</span>
            </div>
            {activeProviderMeta && <StatusBadge status={activeProviderMeta.last_status ?? 'pending'} />}
          </div>

          <section className="steward-signal-section">
            <SignalColumnHeader title="Signal Inbox" description="Current normalized findings for this provider" />
            {signalItems.slice(0, 12).map((item) => (
              <SignalRow item={item} key={item.id} />
            ))}
            {!signalItems.length && <div className="steward-empty">No signal items for this provider</div>}
          </section>

          <section className="steward-signal-section">
            <SignalColumnHeader title="Fetch History" description="Recent remote polling results for this provider" />
            {recentFetches.map((fetch) => (
              <article className="steward-event-row" key={fetch.id}>
                <div>
                  <b>{fetch.provider}</b>
                  <time dateTime={fetch.completed_at}>{relativeTime(fetch.completed_at)}</time>
                </div>
                <p>{fetch.summary}</p>
              </article>
            ))}
            {!recentFetches.length && <div className="steward-empty">No recent fetches for this provider</div>}
          </section>
        </div>
      </div>
    </section>
  );
}

function SignalColumnHeader({ description, title }: { description: string; title: string }) {
  return (
    <div className="steward-column-head">
      <b>{title}</b>
      <span>{description}</span>
    </div>
  );
}

function Metric({ label, value }: { label: string; value: number | string }) {
  return (
    <div className="rounded-[var(--radius)] border border-[var(--line)] bg-[var(--surface-2)] p-3">
      <span className="font-mono text-[11px] font-semibold uppercase text-[var(--muted)]">{label}</span>
      <b className="mt-1 block text-2xl font-normal text-[var(--ink)]">{value}</b>
    </div>
  );
}

function PanelTitle({ description, icon, title }: { description?: string; icon?: ReactNode; title: string }) {
  return (
    <div className="steward-panel-title">
      {icon}
      <div>
        <h3>{title}</h3>
        {description && <p>{description}</p>}
      </div>
    </div>
  );
}

function MirrorNavItem({
  active = false,
  icon,
  label,
  onSelect,
  tab,
  value,
}: {
  active?: boolean;
  icon: ReactNode;
  label: string;
  onSelect: () => void;
  tab: StewardMirrorTab;
  value: string;
}) {
  return (
    <button
      aria-controls={`steward-panel-${tab}`}
      aria-selected={active}
      className={`steward-mirror-nav-item ${active ? 'active' : ''}`}
      id={`steward-tab-${tab}`}
      onClick={onSelect}
      role="tab"
      type="button"
    >
      {icon}
      <span>{label}</span>
      <b>{value}</b>
    </button>
  );
}

function SchedulerLane({ active, capacity, icon, label, queued }: { active: number; capacity: number; icon: ReactNode; label: string; queued: number }) {
  const slots = Math.max(capacity, active, 1);
  return (
    <div className="steward-scheduler-lane">
      <div className="steward-scheduler-lane-head">
        {icon}
        <span>{label}</span>
      </div>
      <div className="slot-row" aria-hidden="true">
        {Array.from({ length: slots }).map((_, index) => (
          <span className={`slot ${index < active ? 'active' : ''}`} key={`${label}-${index}`} />
        ))}
      </div>
      <div className="steward-scheduler-lane-meta">
        <span>active <b>{active}</b></span>
        <span>queued <b>{queued}</b></span>
      </div>
    </div>
  );
}

function ProviderTab({ active, onSelect, provider }: { active: boolean; onSelect: () => void; provider: PublicStewardProvider }) {
  return (
    <button
      aria-selected={active}
      className={`steward-provider-tab ${active ? 'active' : ''}`}
      onClick={onSelect}
      role="tab"
      type="button"
    >
      <span className="steward-provider-tab-main">
        <span className="truncate font-mono text-xs font-semibold">{provider.provider}</span>
        <StatusBadge status={provider.last_status ?? 'pending'} />
      </span>
      <small>{providerScheduleLabel(provider)}</small>
    </button>
  );
}

function SignalRow({ item }: { item: PublicStewardSignalItem }) {
  return (
    <article className="steward-row">
      <RadioTower className="size-4" />
      <span>
        <b>{item.title}</b>
        <small>{item.provider} / {item.kind}</small>
      </span>
      <StatusBadge status={item.status} />
    </article>
  );
}

export function StewardTaskDetail({ detail, loaded, taskId }: { detail: PublicStewardTaskDetail | null; loaded: boolean; taskId: string }) {
  if (!detail) {
    return (
      <main className="task-page-frame">
        <section className="task-page-shell">
          <div className="empty-state">
            {loaded ? (
              <>Public detail for <span className="font-mono">{taskId}</span> has not been published yet.</>
            ) : (
              'Loading task detail.'
            )}
          </div>
        </section>
      </main>
    );
  }
  const task = detail.task;
  const flow = publicTaskFlow(detail);
  const latestAttemptNumber = detail.attempts.at(-1)?.attempt ?? null;
  const timelineEvents = [...detail.events].reverse();
  return (
    <main className="task-page-frame">
      <section className="task-page-shell">
        <header className="task-page-topbar">
          <Link className="task-back-link" href="/steward">
            <ArrowLeft className="size-4" />
            Back to dashboard
          </Link>
          <span className="font-mono text-xs text-[var(--muted)]">snapshot {relativeTime(detail.generated_at)}</span>
        </header>

        <section className="panel task-overview-card" aria-label="Task overview">
          <PanelTitle icon={<Activity size={17} />} title="Overview" />
          <div className="task-overview-head">
            <div className="task-title-row">
              <h1>{task.title}</h1>
              <StatusBadge status={task.status} />
            </div>
            <p>{task.summary || `${task.kind} / ${task.worker}`}</p>
            <div className="task-overview-meta" aria-label="Task facts">
              <FactPill label="Task" mono value={task.id} />
              <FactPill label="Type" value={task.kind} />
              <FactPill label="Agent" value={task.worker} />
              <FactPill label="Updated" mono value={shortDate(task.updated_at)} />
              <FactPill label="Attempts" mono value={String(detail.attempts.length)} />
              <FactPill label="Validations" mono value={String(detail.validations.length)} />
              {detail.remote.commit && detail.remote.commit_url && (
                <a className="steward-commit-link" href={detail.remote.commit_url} rel="noreferrer" target="_blank">
                  <GitBranch className="size-4" />
                  <span>{shortSha(detail.remote.commit)}</span>
                </a>
              )}
            </div>
          </div>
        </section>

        <div className="task-detail-layout">
          <main className="task-detail-main">
            <TaskFlowPanel flow={flow} />
            <div className="attempt-stack page-stack">
              {detail.attempts.length ? (
                [...detail.attempts].reverse().map((attempt) => (
                  <AttemptCard
                    activeStage={flow.activeKey}
                    attempt={attempt}
                    isActiveAttempt={attempt.attempt === latestAttemptNumber}
                    key={`${attempt.attempt}-${attempt.label}`}
                    taskPrompt={task.spec.prompt || ''}
                  />
                ))
              ) : (
                <section className="steward-panel">
                  <div className="steward-empty">No worker, validation, or reviewer run has been captured yet.</div>
                </section>
              )}
            </div>
          </main>

          <aside className="task-detail-aside">
            <section className="panel task-timeline-panel">
              <PanelTitle icon={<ListChecks size={17} />} title="Timeline" />
              <ol className="timeline compact">
                {timelineEvents.map((event) => (
                  <PublicTimelineEvent event={event} key={`${event.kind}-${event.created_at}`} />
                ))}
                {!timelineEvents.length && <li className="muted">No events recorded</li>}
              </ol>
            </section>
          </aside>
        </div>
      </section>
    </main>
  );
}

function FactPill({ label, mono = false, value }: { label: string; mono?: boolean; value: string }) {
  return (
    <span className="fact-pill">
      <b>{label}</b>
      <span className={mono ? 'mono' : ''}>{value || '-'}</span>
    </span>
  );
}

function TaskFlowPanel({ flow }: { flow: PublicTaskFlow }) {
  const graph = publicPipelineGraph(flow);
  return (
    <section className="panel task-flow-panel" aria-label="Task iteration flow">
      <PanelTitle icon={<GitBranch size={17} />} title="Current Iteration" />
      <div className="pipeline-graph" aria-label="Task pipeline graph">
        <ReactFlow
          defaultViewport={{ x: 34, y: 18, zoom: 1 }}
          edges={graph.edges}
          edgesFocusable={false}
          elementsSelectable={false}
          fitView={false}
          maxZoom={1}
          minZoom={1}
          nodeTypes={publicPipelineNodeTypes}
          nodes={graph.nodes}
          nodesConnectable={false}
          nodesDraggable={false}
          nodesFocusable={false}
          panOnDrag={false}
          panOnScroll={false}
          preventScrolling={false}
          proOptions={{ hideAttribution: true }}
          style={{ width: '760px', height: '206px' }}
          zoomOnDoubleClick={false}
          zoomOnPinch={false}
          zoomOnScroll={false}
        >
          <Background color="#e0e0e0" gap={18} size={1} />
        </ReactFlow>
      </div>
    </section>
  );
}

const PUBLIC_PIPELINE_NODE_WIDTH = 150;
const PUBLIC_PIPELINE_NODE_HEIGHT = 76;
const PUBLIC_PIPELINE_BOUND_SIZE = 1;

const publicPipelineNodeTypes = {
  pipeline: PublicPipelineNodeCard,
};

function PublicPipelineNodeCard({ data }: NodeProps<PublicPipelineNode>) {
  if (!data.stage) {
    return <span className="pipeline-fit-bound" aria-hidden="true" />;
  }
  const stage = data.stage;
  return (
    <article className={`pipeline-node ${stage.state}`}>
      <Handle className="pipeline-node-handle" id="left" position={Position.Left} type="target" />
      <Handle className="pipeline-node-handle" id="right" position={Position.Right} type="source" />
      <Handle className="pipeline-node-handle" id="top-source" position={Position.Top} type="source" />
      <Handle className="pipeline-node-handle" id="top-target" position={Position.Top} type="target" />
      <Handle className="pipeline-node-handle" id="bottom-source" position={Position.Bottom} type="source" />
      <Handle className="pipeline-node-handle" id="bottom-target" position={Position.Bottom} type="target" />
      <div className="pipeline-node-head">
        <span className="pipeline-node-dot">{stage.state === 'active' ? <Spinner /> : stageIcon(stage.state)}</span>
        <b>{stage.label}</b>
      </div>
      <p>{stage.detail}</p>
    </article>
  );
}

function publicPipelineGraph(flow: PublicTaskFlow): { nodes: PublicPipelineNode[]; edges: PublicPipelineEdge[] } {
  const fitBoundIds = ['fit-top-left', 'fit-top-right', 'fit-bottom-left', 'fit-bottom-right'];
  const positions: Record<PublicTaskStageKey, { x: number; y: number }> = {
    code: { x: 0, y: 52 },
    validation: { x: 178, y: 52 },
    review: { x: 356, y: 52 },
    integration: { x: 534, y: 52 },
  };
  const stages = Object.fromEntries(flow.stages.map((stage) => [stage.key, stage])) as Record<PublicTaskStageKey, PublicTaskStage>;
  const nodes: PublicPipelineNode[] = [
    ...fitBoundIds.map((id, index) => ({
      id,
      type: 'pipeline' as const,
      position: { x: index % 2 === 0 ? -8 : 684, y: index < 2 ? -8 : 176 },
      data: {},
      width: PUBLIC_PIPELINE_BOUND_SIZE,
      height: PUBLIC_PIPELINE_BOUND_SIZE,
      initialWidth: PUBLIC_PIPELINE_BOUND_SIZE,
      initialHeight: PUBLIC_PIPELINE_BOUND_SIZE,
      measured: {
        width: PUBLIC_PIPELINE_BOUND_SIZE,
        height: PUBLIC_PIPELINE_BOUND_SIZE,
      },
      draggable: false,
      selectable: false,
      focusable: false,
      connectable: false,
      className: 'pipeline-bound-node',
      ariaLabel: 'Pipeline fit boundary',
    })),
    ...flow.stages.map((stage) => ({
      id: stage.key,
      type: 'pipeline' as const,
      position: positions[stage.key],
      data: { stage },
      width: PUBLIC_PIPELINE_NODE_WIDTH,
      height: PUBLIC_PIPELINE_NODE_HEIGHT,
      initialWidth: PUBLIC_PIPELINE_NODE_WIDTH,
      initialHeight: PUBLIC_PIPELINE_NODE_HEIGHT,
      measured: {
        width: PUBLIC_PIPELINE_NODE_WIDTH,
        height: PUBLIC_PIPELINE_NODE_HEIGHT,
      },
      draggable: false,
      selectable: false,
      focusable: false,
      connectable: false,
    })),
  ];
  const edges: PublicPipelineEdge[] = [
    publicForwardEdge('code-validation', 'code', 'validation', stages.code.state),
    publicForwardEdge('validation-review', 'validation', 'review', stages.validation.state),
    publicForwardEdge('review-integration', 'review', 'integration', stages.review.state),
    publicFeedbackEdge('validation-code', 'validation', 'code', publicFeedbackLoopLabel('validation', flow.loops.validation), flow.loops.validation > 0, 'validation'),
    publicFeedbackEdge('review-code', 'review', 'code', publicFeedbackLoopLabel('review', flow.loops.review), flow.loops.review > 0, 'review'),
    publicFeedbackEdge('integration-code', 'integration', 'code', publicFeedbackLoopLabel('integration', flow.loops.integration), flow.loops.integration > 0, 'integration'),
  ];
  return { nodes, edges };
}

function publicForwardEdge(
  id: string,
  source: PublicTaskStageKey,
  target: PublicTaskStageKey,
  state: PublicTaskStageState,
): PublicPipelineEdge {
  return {
    id,
    source,
    target,
    sourceHandle: 'right',
    targetHandle: 'left',
    type: 'smoothstep',
    className: `pipeline-edge ${state}`,
    markerEnd: { type: MarkerType.ArrowClosed, color: state === 'complete' || state === 'active' ? '#0f62fe' : '#c6c6c6' },
    selectable: false,
  };
}

function publicFeedbackEdge(
  id: string,
  source: PublicTaskStageKey,
  target: PublicTaskStageKey,
  label: string,
  active: boolean,
  kind: 'integration' | 'review' | 'validation',
): PublicPipelineEdge {
  const above = kind === 'review';
  const offset = kind === 'integration' ? 46 : kind === 'review' ? 34 : 24;
  return {
    id,
    source,
    target,
    sourceHandle: above ? 'top-source' : 'bottom-source',
    targetHandle: above ? 'top-target' : 'bottom-target',
    type: 'smoothstep',
    label,
    className: `pipeline-edge feedback ${kind} ${active ? 'active' : 'muted'}`,
    pathOptions: { borderRadius: 18, offset },
    labelBgPadding: [6, 3],
    labelBgBorderRadius: 4,
    labelBgStyle: { fill: active ? '#edf5ff' : '#f4f4f4' },
    labelStyle: {
      fill: active ? '#002d9c' : '#6f6f6f',
      fontSize: 11,
      fontWeight: 700,
    },
    markerEnd: { type: MarkerType.ArrowClosed, color: active ? '#0f62fe' : '#c6c6c6' },
    selectable: false,
  };
}

function publicFeedbackLoopLabel(kind: 'integration' | 'review' | 'validation', count: number) {
  return count > 0 ? `${kind} x${count}` : `${kind} feedback`;
}

function AttemptCard({
  activeStage,
  attempt,
  isActiveAttempt,
  taskPrompt,
}: {
  activeStage: PublicTaskStageKey;
  attempt: PublicStewardAttempt;
  isActiveAttempt: boolean;
  taskPrompt: string;
}) {
  const stageTab = defaultAttemptTab(activeStage);
  const [open, setOpen] = useState(isActiveAttempt);
  const [userCollapsed, setUserCollapsed] = useState(false);
  const [selectedTab, setSelectedTab] = useState<PublicAttemptTab>('transcript');
  const [userSelectedTab, setUserSelectedTab] = useState(false);
  const visibleOpen = open || (isActiveAttempt && !userCollapsed);
  const active = isActiveAttempt && !userSelectedTab ? stageTab : selectedTab;
  const hasPatch = Boolean(attempt.patch?.text || attempt.patch?.url);
  const hasReview = Boolean(attempt.review || attempt.reviewer?.transcript?.text || attempt.reviewer?.last_message?.text || attempt.reviewer?.transcript?.url);
  const tabs: Array<{ key: PublicAttemptTab; label: string; meta?: string | number }> = [
    { key: 'transcript', label: 'Transcript', meta: attempt.worker?.transcript || attempt.worker?.last_message ? 'captured' : undefined },
    { key: 'patch', label: 'Patch', meta: hasPatch ? 'saved' : undefined },
    { key: 'validation', label: 'Validation', meta: attempt.validations.length },
    { key: 'review', label: 'Review', meta: hasReview ? 'ready' : undefined },
  ];
  return (
    <article className={`attempt-card ${isActiveAttempt ? 'active-run' : ''}`}>
      <button
        className="attempt-head"
        aria-expanded={visibleOpen}
        onClick={() => {
          const nextOpen = !visibleOpen;
          setOpen(nextOpen);
          setUserCollapsed(!nextOpen);
        }}
        type="button"
      >
        <div className="attempt-title">
          <ChevronRight className="attempt-chevron" size={16} />
          <div>
            <span className="attempt-kicker mono">attempt {attempt.attempt}</span>
            <h3>{attempt.label}</h3>
          </div>
        </div>
        <div className="attempt-meta">
          <span>{attempt.worker ? 'worker' : 'no worker'}</span>
          <span>{attempt.validations.length} validations</span>
          <span>{attempt.reviewer ? 'reviewed' : 'not reviewed'}</span>
        </div>
      </button>
      {visibleOpen && (
        <div className="attempt-body">
          <div className="attempt-tabs" role="tablist" aria-label={`${attempt.label} run views`}>
            {tabs.map((tab) => (
              <button
                aria-selected={active === tab.key}
                className={active === tab.key ? 'active' : ''}
                key={tab.key}
                onClick={() => {
                  setSelectedTab(tab.key);
                  setUserSelectedTab(true);
                }}
                role="tab"
                type="button"
              >
                <span>{tab.label}</span>
                {tab.meta !== undefined && <b>{tab.meta}</b>}
              </button>
            ))}
          </div>
          <div className="attempt-panel">
            {active === 'transcript' && (
              <RunSection
                artifact={attempt.worker?.transcript ?? attempt.worker?.last_message ?? null}
                prompt={attempt.attempt === 0 ? taskPrompt : ''}
                run={attempt.worker}
                title="Worker transcript"
              />
            )}
            {active === 'patch' && <PatchSection artifact={attempt.patch} />}
            {active === 'validation' && <ValidationList validations={attempt.validations} />}
            {active === 'review' && <ReviewSection attempt={attempt} />}
          </div>
        </div>
      )}
    </article>
  );
}

function RunSection({
  artifact,
  prompt = '',
  run,
  title,
}: {
  artifact: PublicStewardArtifact;
  prompt?: string;
  run: PublicStewardRunArtifact;
  title: string;
}) {
  return (
    <>
      <div className="attempt-section-head">
        <FileText size={15} />
        <h4>{title}</h4>
        {run?.name && <code>{run.name}</code>}
      </div>
      <ArtifactContent artifact={artifact} empty={`No ${title.toLowerCase()} published`}>
        {(text) => (
          <div className="attempt-transcript">
            <TranscriptView
              diagnostics={run?.diagnostics as PublicCodexRunDiagnostics | null | undefined}
              isLiveRun={false}
              prompt={prompt}
              taskId={run?.name || "public-steward-run"}
              text={text}
            />
          </div>
        )}
      </ArtifactContent>
    </>
  );
}

function PatchSection({ artifact }: { artifact: PublicStewardArtifact }) {
  return (
    <div className="run-patch">
      <ArtifactContent artifact={artifact} empty="No saved patch for this iteration">
        {(text) => <CodeBlock diffDisplay="unified-with-split-modal" language="diff" text={text} title="Patch" />}
      </ArtifactContent>
    </div>
  );
}

function ArtifactContent({
  artifact,
  children,
  empty,
}: {
  artifact: PublicStewardArtifact;
  children: (text: string) => ReactNode;
  empty: string;
}) {
  const [remoteText, setRemoteText] = useState<string | null>(null);
  const [remoteError, setRemoteError] = useState<string | null>(null);
  const artifactUrl = artifact?.url;
  useEffect(() => {
    if (!artifactUrl || artifact?.text) {
      setRemoteText(null);
      setRemoteError(null);
      return;
    }
    const url = artifactUrl;
    let cancelled = false;
    setRemoteText(null);
    setRemoteError(null);
    async function loadArtifact() {
      try {
        const response = await fetch(url, { cache: 'no-store' });
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const text = await response.text();
        if (!cancelled) setRemoteText(text);
      } catch (error) {
        if (!cancelled) setRemoteError(error instanceof Error ? error.message : 'Unable to load artifact');
      }
    }
    void loadArtifact();
    return () => {
      cancelled = true;
    };
  }, [artifact?.text, artifactUrl]);

  const text = artifact?.text || remoteText || '';
  if (text) {
    return <>{children(text)}</>;
  }
  if (artifact?.url) {
    return (
      <>
        <div className="empty-state compact">{remoteError ? `Unable to load artifact: ${remoteError}` : 'Loading artifact.'}</div>
      </>
    );
  }
  return <div className="empty-state compact">{empty}</div>;
}

function ReviewSection({ attempt }: { attempt: PublicStewardAttempt }) {
  const review = publicReviewRecord(attempt);
  const reviewerArtifact = attempt.reviewer?.transcript ?? attempt.reviewer?.last_message ?? null;
  return (
    <div className="attempt-review-stack">
      {review ? <ReviewCard review={review} /> : <div className="empty-state compact">No structured review verdict for this attempt</div>}
      <RunSection artifact={reviewerArtifact} run={attempt.reviewer} title="Reviewer transcript" />
    </div>
  );
}

function ValidationList({ validations }: { validations: PublicStewardValidationDetail[] }) {
  const [activeIndex, setActiveIndex] = useState(validations[0]?.index ?? null);
  const activeValidation = validations.find((validation) => validation.index === activeIndex);
  if (!validations.length) return <div className="empty-state compact">No validations for this attempt</div>;
  return (
    <div className="attempt-validation-list">
      {validations.map((validation) => (
        <button
          className={`validation-row ${activeIndex === validation.index ? 'active' : ''}`}
          key={validation.index}
          onClick={() => setActiveIndex(validation.index)}
          type="button"
        >
          {validation.passed ? <CheckCircle2 size={16} /> : <XCircle size={16} />}
          <span className="mono">{validation.command.join(' ')}</span>
          <StatusPill status={validation.passed ? 'succeeded' : 'failed'} />
        </button>
      ))}
      {activeValidation?.log && (
        <ArtifactContent artifact={activeValidation.log} empty="No validation log was published">
          {(text) => <CodeBlock compact text={text} title="Validation log" />}
        </ArtifactContent>
      )}
    </div>
  );
}

function PublicTimelineEvent({ event }: { event: PublicStewardEvent }) {
  const model = publicTimelineModel(event);
  return (
    <li className={`timeline-item ${model.tone}`}>
      <div className="timeline-marker" aria-hidden="true">
        {timelineIcon(event.kind)}
      </div>
      <div className="timeline-card">
        <div className="timeline-head">
          <b className="timeline-kind font-mono">{event.kind}</b>
          <time className="timeline-time font-mono" dateTime={event.created_at}>
            {shortDate(event.created_at)}
          </time>
        </div>
        <div className="timeline-title-row">
          <h3>{model.title}</h3>
          {model.review?.verdict && (
            <span className={`timeline-verdict ${model.review.verdict}`}>
              {model.review.verdict}
            </span>
          )}
        </div>
        {model.description && <p className="timeline-message">{model.description}</p>}
        {model.chips.length > 0 && (
          <div className="timeline-chips">
            {model.chips.map((chip) => (
              <span className={`timeline-chip ${chip.tone || ''}`} key={`${chip.label}-${chip.value}`}>
                <b>{chip.label}</b>
                <span>{chip.value}</span>
              </span>
            ))}
          </div>
        )}
        {model.fields.length > 0 && (
          <dl className="timeline-fields">
            {model.fields.map((field) => (
              <div className="timeline-field" key={`${field.label}-${field.value}`}>
                <dt>{field.label}</dt>
                <dd className={field.kind === 'path' ? 'font-mono path' : undefined}>{field.value}</dd>
              </div>
            ))}
          </dl>
        )}
        {model.review && <PublicReviewTimelineDetails review={model.review} />}
      </div>
    </li>
  );
}

function PublicReviewTimelineDetails({ review }: { review: PublicReviewShape }) {
  const findings = review.findings;
  const gaps = review.validation_gaps;
  if (!review.remaining_risk && findings.length === 0 && gaps.length === 0) return null;
  return (
    <div className="timeline-review">
      {findings.length > 0 && (
        <div>
          <h4>Findings</h4>
          <ul>
            {findings.map((finding, index) => (
              <li key={`${stringValue(finding.title, 'finding')}-${index}`}>
                <b>{stringValue(finding.title, 'Finding')}</b>
                {stringValue(finding.file, '') && (
                  <span className="font-mono">
                    {stringValue(finding.file, '')}
                    {typeof finding.line === 'number' ? `:${finding.line}` : ''}
                  </span>
                )}
              </li>
            ))}
          </ul>
        </div>
      )}
      {gaps.length > 0 && (
        <div>
          <h4>Validation gaps</h4>
          <ul>
            {gaps.map((gap, index) => <li key={`${gap}-${index}`}>{gap}</li>)}
          </ul>
        </div>
      )}
      {review.remaining_risk && (
        <div>
          <h4>Remaining risk</h4>
          <p>{review.remaining_risk}</p>
        </div>
      )}
    </div>
  );
}

function ReviewCard({ review }: { review: PublicReviewRecord }) {
  return (
    <article className="review-card">
      <div className="review-head">
        <div>
          <div className="mono muted">{shortDate(review.created_at)} · attempt {review.attempt}</div>
          <h3>{review.summary || 'Review completed'}</h3>
        </div>
        <span className={`review-verdict ${review.verdict === 'approve' ? 'approve' : review.verdict === 'block' ? 'block' : 'fail'}`}>
          {review.verdict}
        </span>
      </div>
      <div className="review-facts">
        <KeyValue label="Event" value={review.event_kind} />
        {review.exit_code !== null && <KeyValue label="Exit" value={String(review.exit_code)} />}
        <KeyValue label="Findings" value={String(review.findings.length)} />
        <KeyValue label="Validation gaps" value={String(review.validation_gaps.length)} />
      </div>
      {review.remaining_risk && (
        <section className="review-note">
          <h4>Remaining Risk</h4>
          <p>{review.remaining_risk}</p>
        </section>
      )}
      {review.command && (
        <section className="review-note">
          <h4>Command</h4>
          <p className="mono">{review.command}</p>
        </section>
      )}
      {review.findings.length > 0 && (
        <>
          <h4>Findings</h4>
          <div className="review-findings">
            {review.findings.map((finding, index) => (
              <div className="review-finding" key={`${finding.file}-${finding.line}-${index}`}>
                <div className="review-finding-title">
                  <span className={`severity severity-${finding.severity}`}>{finding.severity}</span>
                  <b>{finding.title}</b>
                </div>
                <div className="mono muted">
                  {finding.file}{finding.line !== null ? `:${finding.line}` : ''}
                </div>
                <p>{finding.detail}</p>
                <p><b>Recommendation:</b> {finding.recommendation}</p>
              </div>
            ))}
          </div>
        </>
      )}
      {review.validation_gaps.length > 0 && (
        <>
          <h4>Validation Gaps</h4>
          <ul className="review-gaps">
            {review.validation_gaps.map((gap, index) => <li key={`${gap}-${index}`}>{gap}</li>)}
          </ul>
        </>
      )}
    </article>
  );
}

function KeyValue({ label, value }: { label: string; value: string }) {
  return (
    <div className="key-value">
      <span>{label}</span>
      <b className="mono">{value}</b>
    </div>
  );
}

function Fact({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-[var(--radius)] border border-[var(--line)] bg-[var(--surface-2)] p-3">
      <span className="font-mono text-[11px] font-semibold uppercase text-[var(--muted)]">{label}</span>
      <b className="mt-1 block truncate text-sm font-medium text-[var(--ink)]">{value || '-'}</b>
    </div>
  );
}

function StatusBadge({ status }: { status: string }) {
  if (['pushed', 'succeeded', 'ok', 'idle'].includes(status)) return <Badge variant="success">{status}</Badge>;
  if (['running', 'reviewing', 'integrating', 'working', 'planned'].includes(status)) return <Badge variant="primary">{status}</Badge>;
  if (['queued', 'pending'].includes(status)) return <Badge variant="warning">{status}</Badge>;
  if (['failed', 'blocked', 'error', 'attention'].includes(status)) return <Badge variant="danger">{status}</Badge>;
  return <Badge>{status}</Badge>;
}

function StatusPill({ status }: { status: string }) {
  return <span className={`status status-${status}`}>{status}</span>;
}

function isPublicIntegrationTask(task: PublicStewardTask) {
  return task.kind === 'integration' || task.worker === 'integration-manager' || task.source === 'integration';
}

function integrationTaskTitle(task: PublicStewardTask) {
  return task.title.replace(/^Integrate\b/, 'Integration');
}

function publicTaskCounts(tasks: PublicStewardTask[]) {
  const userTasks = tasks.filter((task) => !isPublicIntegrationTask(task));
  return {
    active: userTasks.filter((task) => ['running', 'reviewing', 'integrating'].includes(task.status)).length,
    attention: userTasks.filter((task) => ['blocked', 'failed', 'cancelled'].includes(task.status)).length,
    completed: userTasks.filter((task) => ['succeeded', 'pushed', 'no_changes', 'blocked', 'failed', 'cancelled'].includes(task.status)).length,
    integration: tasks.length - userTasks.length,
    queued: userTasks.filter((task) => task.status === 'queued').length,
    tasks: userTasks.length,
  };
}

function publicReviewRecord(attempt: PublicStewardAttempt): PublicReviewRecord | null {
  if (!attempt.review) return null;
  const stored = attempt.review;
  return {
    attempt: attempt.attempt,
    command: stringValue(stored.command, ''),
    created_at: stringValue(stored.created_at, attempt.updated_at || attempt.started_at || ''),
    event_kind: stringValue(stored.event_kind, 'iteration.review'),
    exit_code: typeof stored.exit_code === 'number' ? stored.exit_code : attempt.reviewer?.exit_code ?? null,
    findings: findingArray(stored.findings),
    remaining_risk: stringValue(stored.remaining_risk, ''),
    summary: stringValue(stored.summary, ''),
    validation_gaps: stringArray(stored.validation_gaps),
    verdict: stringValue(stored.verdict, 'review'),
  };
}

function findingArray(value: unknown): PublicReviewFinding[] {
  if (!Array.isArray(value)) return [];
  return value.filter(isRecord).map((item) => ({
    detail: stringValue(item.detail, ''),
    file: stringValue(item.file, ''),
    line: typeof item.line === 'number' ? item.line : null,
    recommendation: stringValue(item.recommendation, ''),
    severity: stringValue(item.severity, 'info'),
    title: stringValue(item.title, 'Finding'),
  }));
}

function stringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.map(String) : [];
}

function publicTimelineModel(event: PublicStewardEvent): PublicTimelineModel {
  const data = event.data || {};
  const messageRecord = parseRecord(event.message);
  const review = reviewShape(data.review) || reviewShape(messageRecord);
  const base: PublicTimelineModel = {
    title: humanizeKind(event.kind),
    description: cleanMessage(event.message, messageRecord),
    tone: timelineTone(event.kind),
    chips: primitiveChips(data),
    fields: pathFields(data),
    review: null,
  };

  if (event.kind === 'review.finished' && review) {
    return {
      ...base,
      title: review.verdict === 'approve' ? 'Review approved' : 'Review blocked',
      description: review.summary,
      tone: review.verdict === 'approve' ? 'success' : 'danger',
      chips: [
        { label: 'verdict', value: review.verdict, tone: review.verdict === 'approve' ? 'success' : 'danger' },
        { label: 'attempt', value: stringValue(data.attempt, '-') },
        { label: 'findings', value: String(review.findings.length) },
        { label: 'gaps', value: String(review.validation_gaps.length) },
      ],
      review,
    };
  }

  if (event.kind === 'review.failed' || event.kind === 'review.invalid_output') {
    return {
      ...base,
      title: event.kind === 'review.failed' ? 'Review failed' : 'Review returned invalid output',
      description: base.description || stringValue(data.summary, ''),
      tone: 'danger',
      chips: [
        { label: 'attempt', value: stringValue(data.attempt, '-') },
        { label: 'run', value: stringValue(data.review_run, '-') },
        { label: 'retryable', value: stringValue(data.retryable, '-') },
        { label: 'exit', value: stringValue(data.exit_code, '-') },
      ],
    };
  }

  if (event.kind === 'task.status') {
    return {
      ...base,
      title: stringValue(data.summary, `Task moved to ${event.message}`),
      description: '',
      tone: statusTone(event.message),
      chips: [
        { label: 'status', value: event.message, tone: statusTone(event.message) },
        { label: 'phase', value: stringValue(data.phase, '-') },
      ],
    };
  }

  if (event.kind === 'worktree.ready') {
    return {
      ...base,
      title: 'Worktree ready',
      description: '',
      tone: 'success',
      chips: [],
      fields: [
        { label: 'Worktree', value: event.message, kind: 'path' },
        ...fieldIf('Branch', data.branch),
      ],
    };
  }

  if (event.kind === 'patch.saved') {
    return {
      ...base,
      title: 'Patch saved',
      description: '',
      tone: 'success',
      chips: [{ label: 'label', value: stringValue(data.label, '-') }],
      fields: [{ label: 'Patch', value: event.message, kind: 'path' }],
    };
  }

  if (event.kind === 'validation.failed') {
    const failed = Array.isArray(data.failed) ? data.failed : [];
    return {
      ...base,
      title: 'Validation failed',
      description: event.message,
      tone: 'danger',
      chips: [
        { label: 'label', value: stringValue(data.label, '-') },
        { label: 'failed', value: String(failed.length), tone: 'danger' },
      ],
      fields: [
        ...fieldIf('Patch', data.patch_path, 'path'),
        ...failed.slice(0, 3).flatMap((item, index) =>
          isRecord(item) ? fieldIf(`Command ${index + 1}`, commandText(item.command)) : [],
        ),
      ],
    };
  }

  if (event.kind === 'worker.finished'
    || event.kind === 'worker.revision_finished'
    || event.kind === 'worker.integration_revision_finished') {
    return {
      ...base,
      title: event.kind === 'worker.finished' ? 'Worker finished' : 'Worker revision finished',
      description: '',
      tone: event.message === '0' ? 'success' : 'danger',
      chips: [
        { label: 'exit', value: event.message, tone: event.message === '0' ? 'success' : 'danger' },
        ...chipIf('revision', data.revision),
      ],
    };
  }

  if (event.kind === 'worker.integration_revision_requested') {
    return {
      ...base,
      title: `Integration revision ${stringValue(data.revision, '-')} requested`,
      description: 'Patch did not apply on latest main.',
      tone: 'review',
      chips: [
        { label: 'revision', value: stringValue(data.revision, '-') },
      ],
    };
  }

  if (event.kind === 'worker.revision_requested' && review) {
    return {
      ...base,
      title: `Revision ${stringValue(data.revision, '-')} requested`,
      description: review.summary || base.description,
      tone: 'review',
      chips: [
        { label: 'revision', value: stringValue(data.revision, '-') },
        { label: 'review', value: review.verdict || '-' },
        { label: 'gaps', value: String(review.validation_gaps.length) },
      ],
      review,
    };
  }

  if (event.kind.startsWith('integration.')) {
    return {
      ...base,
      title: humanizeKind(event.kind),
      description: '',
      tone: 'review',
      chips: [
        ...chipIf('created', data.created),
        ...chipIf('task', data.integration_task_id || event.message),
      ],
    };
  }

  if (event.kind === 'main.pushed') {
    return {
      ...base,
      title: 'Pushed to main',
      description: '',
      tone: 'success',
      chips: [{ label: 'commit', value: event.message.slice(0, 12), tone: 'success' }],
    };
  }

  if (event.kind === 'task.created') {
    return {
      ...base,
      title: 'Task created',
      description: event.message,
      tone: 'created',
      chips: [],
    };
  }

  return base;
}

function timelineIcon(kind: string): ReactNode {
  if (kind.includes('failed') || kind.includes('recovered') || kind.includes('invalid')) return <XCircle size={14} />;
  if (kind.includes('finished') || kind.includes('ready') || kind.includes('saved')) return <CheckCircle2 size={14} />;
  if (kind.includes('review')) return <ListChecks size={14} />;
  if (kind.includes('worktree') || kind.includes('branch') || kind.includes('push') || kind.includes('integration')) return <GitBranch size={14} />;
  if (kind.includes('status')) return <Activity size={14} />;
  return <Circle size={10} />;
}

function timelineTone(kind: string): PublicTimelineTone {
  if (kind.includes('failed') || kind.includes('recovered') || kind.includes('invalid')) return 'danger';
  if (kind.includes('finished') || kind.includes('ready') || kind.includes('saved')) return 'success';
  if (kind.includes('review') || kind.includes('integration')) return 'review';
  if (kind.includes('created')) return 'created';
  return 'neutral';
}

function statusTone(status: string): PublicTimelineTone {
  if (['failed', 'blocked', 'cancelled'].includes(status)) return 'danger';
  if (['succeeded', 'pushed', 'no_changes'].includes(status)) return 'success';
  if (['reviewing', 'integrating'].includes(status)) return 'review';
  return 'neutral';
}

function reviewShape(value: unknown): PublicReviewShape | null {
  if (!isRecord(value)) return null;
  const findings = Array.isArray(value.findings) ? value.findings.filter(isRecord) : [];
  return {
    verdict: stringValue(value.verdict, ''),
    summary: stringValue(value.summary, ''),
    findings,
    validation_gaps: Array.isArray(value.validation_gaps) ? value.validation_gaps.map(String) : [],
    remaining_risk: stringValue(value.remaining_risk, ''),
  };
}

function cleanMessage(message: string, parsed: Record<string, unknown> | null): string {
  if (!message || parsed) return '';
  return message;
}

function parseRecord(value: string): Record<string, unknown> | null {
  try {
    const parsed = JSON.parse(value) as unknown;
    return isRecord(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

function primitiveChips(data: Record<string, unknown>): PublicTimelineChip[] {
  return Object.entries(data)
    .filter(([, value]) => isPrimitive(value) && !looksLikePath(String(value)))
    .slice(0, 4)
    .map(([key, value]) => ({ label: labelize(key), value: String(value) }));
}

function pathFields(data: Record<string, unknown>): PublicTimelineField[] {
  return Object.entries(data)
    .filter(([, value]) => typeof value === 'string' && looksLikePath(value))
    .slice(0, 4)
    .map(([key, value]) => ({ label: labelize(key), value: String(value), kind: 'path' }));
}

function fieldIf(label: string, value: unknown, kind: 'path' | 'text' = 'text'): PublicTimelineField[] {
  const text = commandText(value);
  return text ? [{ label, value: text, kind }] : [];
}

function chipIf(label: string, value: unknown): PublicTimelineChip[] {
  const text = stringValue(value, '');
  return text ? [{ label, value: text }] : [];
}

function commandText(value: unknown): string {
  if (Array.isArray(value)) return value.map(String).join(' ');
  return typeof value === 'string' ? value : '';
}

function looksLikePath(value: string) {
  return value.startsWith('/') || value.includes('/worktrees/') || value.includes('/transcripts/') || value.includes('/patches/');
}

function humanizeKind(kind: string) {
  return kind
    .split('.')
    .map((part) => part.replace(/_/g, ' '))
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(' ');
}

function labelize(value: string) {
  return value.replace(/_/g, ' ');
}

function stringValue(value: unknown, fallback: string) {
  if (typeof value === 'string' && value.trim()) return value;
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  return fallback;
}

function isPrimitive(value: unknown) {
  return typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean';
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function publicTaskFlow(detail: PublicStewardTaskDetail): PublicTaskFlow {
  const task = detail.task;
  const attempts = detail.attempts;
  const events = detail.events;
  const activeKey = publicActiveStage(task.status, events);
  const hasWorker = attempts.some((attempt) => Boolean(attempt.worker));
  const hasValidation = attempts.some((attempt) => attempt.validations.length > 0);
  const hasReview = attempts.some((attempt) => Boolean(attempt.reviewer || attempt.review));
  const hasIntegration = task.status === 'integrating'
    || task.status === 'pushed'
    || events.some((event) => event.kind.startsWith('integration.') || event.kind === 'main.pushed');
  const blocked = ['blocked', 'failed', 'cancelled'].includes(task.status) ? activeKey : null;
  const stages: PublicTaskStage[] = [
    {
      detail: publicStageDetail('code', events, hasWorker),
      key: 'code',
      label: 'Code Generation',
      state: publicStageState('code', activeKey, hasWorker, blocked, task.status),
    },
    {
      detail: publicStageDetail('validation', events, hasValidation),
      key: 'validation',
      label: 'Validation',
      state: publicStageState('validation', activeKey, hasValidation, blocked, task.status),
    },
    {
      detail: publicStageDetail('review', events, hasReview),
      key: 'review',
      label: 'Review',
      state: publicStageState('review', activeKey, hasReview, blocked, task.status),
    },
    {
      detail: publicStageDetail('integration', events, hasIntegration),
      key: 'integration',
      label: 'Integration',
      state: publicStageState('integration', activeKey, hasIntegration, blocked, task.status),
    },
  ];
  return {
    activeKey,
    loops: {
      integration: events.filter((event) => event.kind === 'worker.integration_revision_requested').length,
      review: events.filter((event) => event.kind === 'worker.revision_requested').length,
      validation: events.filter((event) => event.kind === 'worker.validation_revision_requested').length,
    },
    stages,
  };
}

function publicActiveStage(status: string, events: PublicStewardEvent[]): PublicTaskStageKey {
  const latestEvent = [...events].reverse().find((event) => publicEventStage(event) !== null);
  if (status === 'integrating' || status === 'pushed' || latestEvent?.kind.startsWith('integration.') || latestEvent?.kind === 'main.pushed') return 'integration';
  if (status === 'reviewing' || publicEventStage(latestEvent) === 'review') return 'review';
  if (publicEventStage(latestEvent) === 'validation') return 'validation';
  return 'code';
}

function publicStageState(
  key: PublicTaskStageKey,
  activeKey: PublicTaskStageKey,
  complete: boolean,
  blocked: PublicTaskStageKey | null,
  status: string,
): PublicTaskStageState {
  if (blocked === key) return 'blocked';
  if (key === activeKey && ['queued', 'running', 'reviewing', 'integrating'].includes(status)) return 'active';
  return complete ? 'complete' : 'pending';
}

function publicStageDetail(key: PublicTaskStageKey, events: PublicStewardEvent[], complete: boolean) {
  const event = [...events].reverse().find((item) => publicEventStage(item) === key);
  if (!event) return publicFallbackStageDetail(key, complete);
  if (key === 'code') {
    if (event.kind === 'worktree.ready') return 'Worktree ready';
    if (event.kind.includes('revision_requested')) return 'Revision requested';
    if (event.kind.includes('finished')) return event.message || 'Worker finished';
    return 'Worker activity recorded';
  }
  if (key === 'validation') {
    if (event.kind === 'validation.failed') return 'Validation failed';
    if (event.kind === 'patch.saved') return 'Patch saved after validation';
    return event.message || 'Validation updated';
  }
  if (key === 'review') {
    if (event.kind === 'review.finished') return 'Review verdict recorded';
    if (event.kind === 'review.failed') return 'Review failed';
    if (event.kind === 'review.invalid_output') return 'Review returned invalid output';
    return 'Review activity recorded';
  }
  if (event.kind === 'main.pushed') return `Pushed ${shortSha(event.message)}`;
  if (event.kind === 'integration.queued') return 'Integration queued';
  if (event.kind === 'integration.started') return 'Integration started';
  return 'Integration activity recorded';
}

function publicFallbackStageDetail(key: PublicTaskStageKey, complete: boolean) {
  if (key === 'code') return complete ? 'Worker session captured' : 'Waiting for worker';
  if (key === 'validation') return complete ? 'Validation gates recorded' : 'No validation run yet';
  if (key === 'review') return complete ? 'Reviewer verdict recorded' : 'Waiting for review';
  return complete ? 'Integration activity recorded' : 'Waiting for integration';
}

function publicEventStage(event?: PublicStewardEvent): PublicTaskStageKey | null {
  const kind = event?.kind || '';
  const phase = typeof event?.data.phase === 'string' ? event.data.phase : '';
  if (kind === 'task.status' && phase === 'validation') return 'validation';
  if (kind.startsWith('worker.') || kind === 'worker.finished' || kind === 'worktree.ready') return 'code';
  if (kind.startsWith('validation.') || kind === 'patch.saved') return 'validation';
  if (kind.startsWith('review.')) return 'review';
  if (kind.startsWith('integration.') || kind === 'main.pushed') return 'integration';
  return null;
}

function stageIcon(state: PublicTaskStageState) {
  if (state === 'complete') return <CheckCircle2 size={15} />;
  if (state === 'blocked') return <XCircle size={15} />;
  if (state === 'active') return <span className="live-spinner" aria-label="active" />;
  return <Circle size={12} />;
}

function Spinner() {
  return <span className="live-spinner" aria-label="active" />;
}

function defaultAttemptTab(stage: PublicTaskStageKey): PublicAttemptTab {
  if (stage === 'validation') return 'validation';
  if (stage === 'review') return 'review';
  if (stage === 'integration') return 'patch';
  return 'transcript';
}

function relativeTime(value: string | null | undefined) {
  if (!value) return '-';
  const ms = Date.now() - new Date(value).getTime();
  if (!Number.isFinite(ms)) return '-';
  const abs = Math.abs(ms);
  const suffix = ms >= 0 ? 'ago' : 'from now';
  if (abs < 60_000) return `${Math.max(1, Math.round(abs / 1000))}s ${suffix}`;
  if (abs < 3_600_000) return `${Math.round(abs / 60_000)}m ${suffix}`;
  if (abs < 86_400_000) return `${Math.round(abs / 3_600_000)}h ${suffix}`;
  return `${Math.round(abs / 86_400_000)}d ${suffix}`;
}

function shortDate(value: string) {
  if (!value) return '-';
  return new Intl.DateTimeFormat(undefined, { dateStyle: 'short', timeStyle: 'medium' }).format(new Date(value));
}

function compactDate(value: string) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const minute = 60 * 1000;
  const hour = 60 * minute;
  const day = 24 * hour;
  if (diffMs >= 0 && diffMs < minute) return 'now';
  if (diffMs >= 0 && diffMs < hour) return `${Math.floor(diffMs / minute)}m`;
  if (diffMs >= 0 && diffMs < day) return `${Math.floor(diffMs / hour)}h`;
  if (diffMs >= 0 && diffMs < 7 * day) return `${Math.floor(diffMs / day)}d`;
  return date.toLocaleDateString(undefined, { month: 'numeric', day: 'numeric' });
}

function providerScheduleLabel(provider: PublicStewardProvider) {
  if (provider.due || provider.idle_due) return 'Due now';
  const nextDue = provider.idle_next_due_at ?? provider.next_due_at;
  if (!nextDue) return 'No scheduled fetch';
  const ms = new Date(nextDue).getTime() - Date.now();
  if (!Number.isFinite(ms)) return 'No scheduled fetch';
  return ms < 0 ? `Overdue by ${durationText(Math.abs(ms))}` : `Next in ${durationText(ms)}`;
}

function durationText(ms: number) {
  if (ms < 60_000) return `${Math.max(1, Math.round(ms / 1000))}s`;
  if (ms < 3_600_000) return `${Math.round(ms / 60_000)}m`;
  if (ms < 86_400_000) return `${Math.round(ms / 3_600_000)}h`;
  return `${Math.round(ms / 86_400_000)}d`;
}

function shortSha(value: string) {
  return value.length > 12 ? value.slice(0, 12) : value;
}

function publicTaskDetailJsonPath(taskId: string) {
  return `/steward/data/tasks/${encodeURIComponent(taskId)}.json`;
}

function formatBytes(value: number) {
  if (!Number.isFinite(value) || value <= 0) return '0 B';
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${Math.round(value / 1024)} KiB`;
  return `${(value / (1024 * 1024)).toFixed(1)} MiB`;
}

function jsonText(value: unknown) {
  return JSON.stringify(value, null, 2);
}

export function StewardUnavailableNotice() {
  return (
    <div className="rounded-[var(--radius)] border border-[var(--line)] bg-[var(--surface-2)] p-4 text-sm text-[var(--muted)]">
      <div className="mb-2 flex items-center gap-2 font-medium text-[var(--ink)]">
        <AlertTriangle className="size-4 text-[var(--warning)]" />
        Public Steward mirror unavailable
      </div>
      The daemon will publish this file after its next state change.
    </div>
  );
}

export function StewardFreshness({ state }: { state: PublicStewardState | null }) {
  const stale = state ? Date.now() - new Date(state.generated_at).getTime() > 15 * 60_000 : true;
  return (
    <div className="flex items-center gap-2 font-mono text-xs text-[var(--muted)]">
      {stale ? <AlertTriangle className="size-4 text-[var(--warning)]" /> : <CheckCircle2 className="size-4 text-[var(--ok)]" />}
      <span>{state ? `snapshot ${relativeTime(state.generated_at)}` : 'waiting for snapshot'}</span>
    </div>
  );
}

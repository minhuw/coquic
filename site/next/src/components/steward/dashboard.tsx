'use client';

import Link from 'next/link';
import {
  Activity,
  Circle,
  ChevronLeft,
  ChevronRight,
  ExternalLink,
  FileText,
  GitBranch,
  Inbox,
  ListChecks,
  RadioTower,
  Route,
  Settings2,
  ShieldCheck,
} from 'lucide-react';
import { type ReactNode, useEffect, useState } from 'react';

import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { classifyStewardFreshness, stewardFreshnessLabel } from '@/lib/steward-freshness';
import { paginateStewardItems } from '@/lib/steward-pagination';

import { usePublicStewardState, type StewardFetchError } from './data';
import {
  handleTabKeyDown,
  PanelTitle,
  relativeTime,
  shortDate,
  shortSha,
  StatusBadge,
  StatusPill,
  StewardFreshness,
} from './shared';
import type {
  PublicStewardProvider,
  PublicStewardSignalItem,
  PublicStewardState,
  PublicStewardTask,
} from './types';

type StewardMirrorTab = 'overview' | 'tasks' | 'signals' | 'audit' | 'configuration';

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
  audit: {
    description: 'Invariant findings reported by the Steward storage audit.',
    eyebrow: 'Integrity',
    title: 'Audit findings',
  },
  configuration: {
    description: 'Sanitized operating configuration published for monitoring.',
    eyebrow: 'Configuration',
    title: 'Public configuration',
  },
};

export function StewardSnapshotCardLive() {
  const monitor = usePublicStewardState();
  return <StewardSnapshotCard state={monitor.state} fetchError={monitor.error} />;
}

export function StewardDashboardLive() {
  const monitor = usePublicStewardState();
  return (
    <div className="grid gap-4 steward-public-live">
      <StewardDashboard state={monitor.state} fetchError={monitor.error} loading={monitor.loading} />
    </div>
  );
}

export function StewardSnapshotCard({
  state,
  fetchError = null,
}: {
  state: PublicStewardState | null;
  fetchError?: StewardFetchError;
}) {
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
            <StewardFreshness state={state} fetchError={Boolean(fetchError)} />
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

export function StewardDashboard({
  state,
  fetchError = null,
  loading = false,
}: {
  state: PublicStewardState | null;
  fetchError?: StewardFetchError;
  loading?: boolean;
}) {
  const [activeTab, setActiveTab] = useState<StewardMirrorTab>('tasks');
  if (!state) {
    return (
      <div className="steward-mirror-shell">
        <Card className="mt-5">
          <CardContent className="p-6 text-sm text-[var(--muted)]">
            <StewardFreshness state={null} />
            <p className="mt-3">
              {loading
                ? 'Loading the latest Steward snapshot.'
                : fetchError === 'incompatible'
                  ? 'The published Steward schema is incompatible with this monitor.'
                  : 'Steward has not published a public snapshot yet.'}
            </p>
          </CardContent>
        </Card>
      </div>
    );
  }
  const counts = publicTaskCounts(state.tasks);
  const activeTask = state.tasks.find((task) => !isPublicIntegrationTask(task) && ['running', 'reviewing', 'integrating'].includes(task.status));
  const tabCopy = STEWARD_MIRROR_TAB_COPY[activeTab];
  const freshness = classifyStewardFreshness(state, Date.now(), Boolean(fetchError));
  const runtime = state.runtime;
  const publication = state.publication;
  return (
    <div className="steward-mirror-shell">
      <aside className="steward-mirror-sidebar" aria-label="Steward public mirror summary">
        <div className="steward-mirror-brand">
          <span className="brand-mark">CS</span>
          <div>
            <div className="brand-title">
              <h2>CoQUIC Steward</h2>
              <span aria-hidden="true" className={`stream-dot ${freshness === 'live' ? 'live' : ''}`} />
            </div>
            <p>{state.repository} / {state.main_branch}</p>
          </div>
        </div>
        <nav className="steward-mirror-nav" aria-label="Steward mirror sections">
          <div className="steward-mirror-nav-tabs" role="tablist" aria-label="Steward mirror sections">
            <MirrorNavItem active={activeTab === 'overview'} icon={<Activity />} label="State" onSelect={() => setActiveTab('overview')} tab="overview" value={state.state} />
            <MirrorNavItem active={activeTab === 'tasks'} icon={<ListChecks />} label="Tasks" onSelect={() => setActiveTab('tasks')} tab="tasks" value={String(counts.tasks)} />
            <MirrorNavItem active={activeTab === 'signals'} icon={<Inbox />} label="Signals" onSelect={() => setActiveTab('signals')} tab="signals" value={String(state.counts.signals)} />
            <MirrorNavItem active={activeTab === 'audit'} icon={<ShieldCheck />} label="Audit" onSelect={() => setActiveTab('audit')} tab="audit" value={String(state.audit.length)} />
            <MirrorNavItem active={activeTab === 'configuration'} icon={<Settings2 />} label="Config" onSelect={() => setActiveTab('configuration')} tab="configuration" value={String(state.configuration.enabled_signals.length)} />
          </div>
          <MirrorNavLink href="/steward/planner" icon={<FileText />} label="Planner" value={String(state.planner_runs?.length ?? 0)} />
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
            <Metric label="Monitor" value={stewardFreshnessLabel(freshness)} />
            <Metric label="Pending" value={state.counts.pending_signals} />
          </div>
        </header>

        <section className="steward-runtime-strip" aria-label="Steward runtime status">
          <StewardFreshness state={state} fetchError={Boolean(fetchError)} />
          <RuntimeFact label="Daemon" value={runtime?.state ?? 'unknown'} />
          <RuntimeFact label="Heartbeat" value={runtime ? relativeTime(runtime.heartbeat_at) : 'unknown'} />
          <RuntimeFact label="Cycle" value={runtime?.current_cycle_reason ?? 'idle'} />
          <RuntimeFact label="Published" value={publication?.last_success_at ? relativeTime(publication.last_success_at) : 'not yet'} />
          {publication?.state === 'failed' && <RuntimeFact label="Publish" value={`failed (${publication.last_failure_category ?? 'unknown'})`} tone="danger" />}
        </section>

        <div
          aria-labelledby={`steward-tab-${activeTab}`}
          className="steward-tab-panel"
          id={`steward-panel-${activeTab}`}
          role="tabpanel"
        >
          {activeTab === 'overview' && <StewardOverviewTab state={state} />}
          {activeTab === 'tasks' && <StewardTasksTab state={state} />}
          {activeTab === 'signals' && <StewardSignalsTab state={state} />}
          {activeTab === 'audit' && <StewardAuditTab state={state} />}
          {activeTab === 'configuration' && <StewardConfigurationTab state={state} />}
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

function StewardAuditTab({ state }: { state: PublicStewardState }) {
  return (
    <section className="steward-panel steward-audit-panel">
      <PanelTitle icon={<ShieldCheck size={17} />} title="Invariant audit" description="Sanitized findings from the local Steward store." />
      {state.audit.length ? (
        <ul className="steward-audit-list">
          {state.audit.map((finding, index) => (
            <li key={`${finding}-${index}`}>
              <Circle className="size-3" />
              <span>{finding}</span>
            </li>
          ))}
        </ul>
      ) : (
        <div className="steward-empty">No invariant findings were published.</div>
      )}
    </section>
  );
}

function StewardConfigurationTab({ state }: { state: PublicStewardState }) {
  const limits = Object.entries(state.configuration.limits);
  const providers = Object.entries(state.configuration.signal_providers);
  return (
    <section className="steward-panel steward-configuration-panel">
      <PanelTitle icon={<Settings2 size={17} />} title="Public configuration" description="Only sanitized operating values are included in the mirror." />
      <dl className="steward-config-grid">
        <ConfigFact label="Repository" value={state.configuration.repository} />
        <ConfigFact label="Main branch" value={state.configuration.main_branch} />
        <ConfigFact label="Integration mode" value={state.configuration.integration_mode} />
        <ConfigFact label="Local-only" value={state.configuration.local_only ? 'yes' : 'no'} />
        <ConfigFact label="Scheduler wait" value={`${state.configuration.scheduler_wait_interval_sec}s`} />
        <ConfigFact label="Enabled signals" value={state.configuration.enabled_signals.join(', ') || 'none'} />
      </dl>
      <div className="steward-config-sections">
        <section>
          <h3>Limits</h3>
          {limits.length ? <ul>{limits.map(([key, value]) => <li key={key}><span>{key}</span><b>{value ?? '-'}</b></li>)}</ul> : <p>Not published</p>}
        </section>
        <section>
          <h3>Provider cadence</h3>
          {providers.length ? <ul>{providers.map(([key, value]) => <li key={key}><span>{key}</span><b>{value.poll_interval_minutes}m</b></li>)}</ul> : <p>No providers enabled</p>}
        </section>
      </div>
    </section>
  );
}

function ConfigFact({ label, value }: { label: string; value: string }) {
  return <div><dt>{label}</dt><dd>{value}</dd></div>;
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
  const pagination = paginateStewardItems(items, page, pageSize);
  useEffect(() => {
    if (page !== pagination.page) setPage(pagination.page);
  }, [page, pagination.page]);
  return {
    ...pagination,
    setPage,
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

        <div
          aria-labelledby={activeProvider ? providerTabId(activeProvider) : undefined}
          className="steward-provider-detail"
          id="steward-provider-panel"
          role="tabpanel"
        >
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
      onKeyDown={handleTabKeyDown}
      tabIndex={active ? 0 : -1}
      role="tab"
      type="button"
    >
      {icon}
      <span>{label}</span>
      <b>{value}</b>
    </button>
  );
}

function MirrorNavLink({
  href,
  icon,
  label,
  value,
}: {
  href: string;
  icon: ReactNode;
  label: string;
  value: string;
}) {
  return (
    <Link className="steward-mirror-nav-item" href={href}>
      {icon}
      <span>{label}</span>
      <b>{value}</b>
    </Link>
  );
}

function providerTabId(provider: string) {
  return `steward-provider-tab-${provider.replace(/[^A-Za-z0-9_-]+/g, '-')}`;
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
      aria-controls="steward-provider-panel"
      aria-selected={active}
      className={`steward-provider-tab ${active ? 'active' : ''}`}
      id={providerTabId(provider.provider)}
      onClick={onSelect}
      onKeyDown={handleTabKeyDown}
      tabIndex={active ? 0 : -1}
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

function RuntimeFact({
  label,
  tone = 'neutral',
  value,
}: {
  label: string;
  tone?: 'neutral' | 'danger';
  value: string;
}) {
  return (
    <div className={`steward-runtime-fact tone-${tone}`}>
      <span>{label}</span>
      <b>{value}</b>
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

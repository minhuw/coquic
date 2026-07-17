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
  ShieldAlert,
  ShieldCheck,
} from 'lucide-react';
import { type ReactNode, useEffect, useState } from 'react';

import { classifyStewardFreshness, stewardFreshnessLabel } from '@/lib/steward-freshness';
import { paginateStewardItems } from '@/lib/steward-pagination';

import { usePublicStewardState, type StewardFetchError } from './data';
import {
  handleTabKeyDown,
  PanelTitle,
  relativeTime,
  shortDate,
  shortSha,
  StewardStatusLabel,
  StewardFreshness,
  stewardStatusTone,
} from './shared';
import type {
  PublicStewardProvider,
  PublicStewardSignalItem,
  PublicStewardState,
  PublicStewardTask,
} from './types';
import styles from './dashboard.module.css';

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
    eyebrow: 'Read-only state',
    title: 'Operations state',
  },
  tasks: {
    description: 'Public snapshot of Steward task lanes and current task links.',
    eyebrow: 'Task evidence',
    title: 'Tasks',
  },
  signals: {
    description: 'Provider schedule, current signal items, and recent fetches.',
    eyebrow: 'Signal evidence',
    title: 'Signals',
  },
  audit: {
    description: 'Invariant findings reported by the Steward storage audit.',
    eyebrow: 'Integrity evidence',
    title: 'Audit findings',
  },
  configuration: {
    description: 'Sanitized operating configuration published for monitoring.',
    eyebrow: 'Published configuration',
    title: 'Public configuration',
  },
};

const STEWARD_MIRROR_TABS: Array<{ icon: ReactNode; key: StewardMirrorTab; label: string }> = [
  { icon: <Activity aria-hidden="true" />, key: 'overview', label: 'State' },
  { icon: <ListChecks aria-hidden="true" />, key: 'tasks', label: 'Tasks' },
  { icon: <Inbox aria-hidden="true" />, key: 'signals', label: 'Signals' },
  { icon: <ShieldCheck aria-hidden="true" />, key: 'audit', label: 'Audit' },
  { icon: <Settings2 aria-hidden="true" />, key: 'configuration', label: 'Config' },
];

export function StewardSnapshotCardLive() {
  const monitor = usePublicStewardState();
  return <StewardSnapshotCard state={monitor.state} fetchError={monitor.error} />;
}

export function StewardDashboardLive() {
  const monitor = usePublicStewardState();
  return <StewardDashboard state={monitor.state} fetchError={monitor.error} loading={monitor.loading} />;
}

export function StewardSnapshotCard({
  state,
  fetchError = null,
}: {
  state: PublicStewardState | null;
  fetchError?: StewardFetchError;
}) {
  const activeTask = state?.tasks.find((task) => !isPublicIntegrationTask(task) && isActiveTask(task));
  const counts = state ? publicTaskCounts(state.tasks) : null;
  return (
    <div className={styles.root}>
      <section className="steward-dashboard-snapshot" aria-label="Steward snapshot">
      <header className="steward-dashboard-snapshot-header">
        <div>
          <span className="steward-dashboard-eyebrow">Public snapshot</span>
          <h2>Steward</h2>
          <p>Autonomous maintenance monitor</p>
        </div>
        <StewardStatus status={state?.state ?? 'idle'} />
      </header>
      <div className="steward-dashboard-snapshot-content">
        <StewardFreshness state={state} fetchError={Boolean(fetchError)} />
        {state ? (
          <>
            <dl className="steward-dashboard-snapshot-facts">
              <SummaryFact label="Active" value={counts?.active ?? 0} />
              <SummaryFact label="Queued" value={counts?.queued ?? 0} />
              <SummaryFact label="Signals" value={state.counts.pending_signals} />
              <SummaryFact label="Completed" value={counts?.completed ?? 0} />
            </dl>
            <div className="steward-dashboard-snapshot-task">
              <span>Current task</span>
              {activeTask ? <Link href={activeTask.detail_url ?? `/steward/tasks/${activeTask.id}`}>{activeTask.title}</Link> : <strong>No active task</strong>}
            </div>
            <Link className="steward-dashboard-link" href="/steward">Open Steward monitor</Link>
          </>
        ) : (
          <p className="steward-dashboard-muted">Waiting for Steward to publish its first public snapshot.</p>
        )}
      </div>
      </section>
    </div>
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
    return loading ? <StewardDashboardLoading /> : <StewardDashboardUnavailable fetchError={fetchError} />;
  }

  const counts = publicTaskCounts(state.tasks);
  const activeTask = state.tasks.find((task) => !isPublicIntegrationTask(task) && isActiveTask(task));
  const tabCopy = STEWARD_MIRROR_TAB_COPY[activeTab];
  const freshness = classifyStewardFreshness(state, Date.now(), Boolean(fetchError));
  const runtime = state.runtime;
  const publication = state.publication;

  return (
    <DashboardSurface>
      <div className="steward-dashboard steward-mirror-shell">
      <section className="steward-dashboard-summary" aria-label="Steward runtime status">
        <div className="steward-dashboard-summary-lead">
          <div>
            <span className="steward-dashboard-eyebrow">Read-only public publication</span>
            <h2>Current state</h2>
            <p className="steward-dashboard-repository">
              <span>{state.repository}</span>
              <span aria-hidden="true">/</span>
              <span>{state.main_branch}</span>
            </p>
          </div>
          <StewardStatus status={state.state} label={state.state} />
        </div>
        <dl className="steward-dashboard-summary-facts">
          <div className="steward-dashboard-summary-fact steward-dashboard-summary-fact--freshness">
            <dt>Monitor freshness</dt>
            <dd><StewardFreshness state={state} fetchError={Boolean(fetchError)} /></dd>
          </div>
          <SummaryFact label="Daemon state" value={runtime?.state ?? 'unknown'} />
          <SummaryFact label="Heartbeat" value={runtime ? relativeTime(runtime.heartbeat_at) : 'unknown'} />
          <SummaryFact label="Current cycle" value={runtime?.current_cycle_reason ?? 'idle'} machine />
          <SummaryFact label="Last publication" value={publication?.last_success_at ? relativeTime(publication.last_success_at) : 'not yet'} />
          <SummaryFact label="Pending signals" value={state.counts.pending_signals} />
          <div className="steward-dashboard-summary-fact steward-dashboard-summary-fact--task">
            <dt>Active task</dt>
            <dd>
              {activeTask ? <Link aria-label={`Active task: ${activeTask.title}`} className="steward-dashboard-inline-action" href={activeTask.detail_url ?? `/steward/tasks/${activeTask.id}`}>{activeTask.title}</Link> : 'No active task'}
            </dd>
          </div>
        </dl>
      </section>

      {fetchError && <StewardRefreshNotice error={fetchError} />}

      <div className="steward-dashboard-workspace">
        <nav className="steward-dashboard-view-navigation" aria-label="Steward views">
          <div className="steward-dashboard-view-navigation-mobile">
            <label htmlFor="steward-view-select">View</label>
            <select
              id="steward-view-select"
              value={activeTab}
              onChange={(event) => setActiveTab(event.target.value as StewardMirrorTab)}
            >
              {STEWARD_MIRROR_TABS.map((tab) => <option key={tab.key} value={tab.key}>{tab.label}</option>)}
            </select>
          </div>
          <div className="steward-dashboard-view-navigation-desktop">
            <div aria-orientation="vertical" className="steward-dashboard-tabs" role="tablist" aria-label="Steward views">
              {STEWARD_MIRROR_TABS.map((tab) => (
                <DashboardViewTab
                  active={activeTab === tab.key}
                  icon={tab.icon}
                  key={tab.key}
                  label={tab.label}
                  onSelect={() => setActiveTab(tab.key)}
                  tab={tab.key}
                  value={viewValue(tab.key, state, counts)}
                />
              ))}
            </div>
          </div>
          <Link aria-label="Planner" className="steward-dashboard-planner-link" href="/steward/planner">
            <FileText aria-hidden="true" />
            <span>Planner</span>
            <span className="steward-dashboard-nav-count">{state.planner_runs?.length ?? 0}</span>
          </Link>
        </nav>

        <section className="steward-dashboard-view" aria-labelledby={`steward-tab-${activeTab}`}>
          <header className="steward-dashboard-view-header">
            <div>
              <span className="steward-dashboard-eyebrow">{tabCopy.eyebrow}</span>
              <h2>{tabCopy.title}</h2>
              <p>{activeTab === 'overview' ? (activeTask ? activeTask.title : 'No active task in the public snapshot') : tabCopy.description}</p>
            </div>
            <div className="steward-dashboard-view-freshness" aria-label="Current monitor conclusion">
              <span>Freshness</span>
              <strong>{stewardFreshnessLabel(freshness)}</strong>
            </div>
          </header>
          <div
            aria-labelledby={`steward-tab-${activeTab}`}
            className="steward-dashboard-tabpanel"
            id={`steward-panel-${activeTab}`}
            role="tabpanel"
            tabIndex={-1}
          >
            {activeTab === 'overview' && <StewardOverviewTab state={state} />}
            {activeTab === 'tasks' && <StewardTasksTab state={state} />}
            {activeTab === 'signals' && <StewardSignalsTab state={state} />}
            {activeTab === 'audit' && <StewardAuditTab state={state} />}
            {activeTab === 'configuration' && <StewardConfigurationTab state={state} />}
          </div>
        </section>
      </div>
      </div>
    </DashboardSurface>
  );
}

function StewardDashboardLoading() {
  return (
    <DashboardSurface>
      <div className="steward-dashboard steward-mirror-shell steward-dashboard-loading" aria-busy="true" data-testid="steward-dashboard-loading">
      <section className="steward-dashboard-summary steward-dashboard-summary-skeleton" aria-label="Loading Steward status">
        <div className="steward-dashboard-skeleton-block steward-dashboard-skeleton-block--lead" />
        <div className="steward-dashboard-skeleton-facts">
          {Array.from({ length: 7 }, (_, index) => <div className="steward-dashboard-skeleton-block" key={index} />)}
        </div>
      </section>
      <div className="steward-dashboard-loading-status">
        <StewardFreshness state={null} />
        <p>Loading the latest Steward snapshot.</p>
      </div>
      <div className="steward-dashboard-workspace steward-dashboard-workspace-skeleton">
        <div className="steward-dashboard-skeleton-navigation">
          {Array.from({ length: 6 }, (_, index) => <div className="steward-dashboard-skeleton-block" key={index} />)}
        </div>
        <div className="steward-dashboard-skeleton-content">
          <div className="steward-dashboard-skeleton-block steward-dashboard-skeleton-block--heading" />
          <div className="steward-dashboard-skeleton-block steward-dashboard-skeleton-block--evidence" />
        </div>
      </div>
      </div>
    </DashboardSurface>
  );
}

function StewardDashboardUnavailable({ fetchError }: { fetchError: StewardFetchError }) {
  const message = fetchError === 'incompatible'
    ? 'The published Steward schema is incompatible with this monitor.'
    : fetchError === 'invalid'
      ? 'The published Steward snapshot is invalid and cannot be displayed.'
      : fetchError === 'unavailable'
        ? 'Steward status could not be reached; no public snapshot is available.'
        : 'Steward has not published a public snapshot yet.';
  return (
    <DashboardSurface>
      <div className="steward-dashboard steward-mirror-shell steward-dashboard-unavailable">
      <section className="steward-dashboard-unavailable-panel" aria-label="Steward publication status">
        <StewardFreshness state={null} />
        <h2>Public snapshot unavailable</h2>
        <p>{message}</p>
      </section>
      </div>
    </DashboardSurface>
  );
}

function DashboardSurface({ children }: { children: ReactNode }) {
  return (
    <div className={`${styles.root} steward-dashboard-root`} data-steward-module="dashboard" data-steward-root="dashboard">
      {children}
    </div>
  );
}

function StewardRefreshNotice({ error }: { error: Exclude<StewardFetchError, null> }) {
  const reason = error === 'incompatible'
    ? 'the latest schema is incompatible'
    : error === 'invalid'
      ? 'the latest publication is invalid'
      : 'the latest transport request failed';
  return (
    <div className="steward-dashboard-refresh-notice" role="status" aria-live="polite">
      <ShieldAlert aria-hidden="true" />
      <span>Showing the last valid snapshot; {reason}.</span>
    </div>
  );
}

function StewardOverviewTab({ state }: { state: PublicStewardState }) {
  const integrationTasks = state.tasks.filter(isPublicIntegrationTask);
  return (
    <div className="steward-dashboard-evidence-grid">
      <section className="steward-dashboard-evidence" aria-labelledby="steward-scheduler-heading">
        <PanelTitle title="Scheduler" description="Serialized capacity and queue state" />
        <div className="steward-dashboard-scheduler-lanes" id="steward-scheduler-heading">
          <SchedulerLane
            active={state.scheduler.source_active}
            capacity={state.scheduler.source_capacity}
            icon={<ListChecks aria-hidden="true" />}
            label="Source"
            queued={state.scheduler.source_queued}
          />
          <SchedulerLane
            active={state.scheduler.integration_active}
            capacity={1}
            icon={<GitBranch aria-hidden="true" />}
            label="Integration"
            queued={state.scheduler.integration_queued}
          />
        </div>
        <div className="steward-dashboard-fact-row">
          <Fact label="Pending wakeups" value={String(state.scheduler.pending_wakeups.length)} />
          <Fact label="Recent wakeups" value={String(state.scheduler.recent_wakeups.length)} />
        </div>
      </section>

      <section className="steward-dashboard-evidence" aria-labelledby="steward-integration-heading">
        <PanelTitle title="Integration" description="Recent integration runs and pushes to main" />
        <div className="steward-dashboard-evidence-heading" id="steward-integration-heading">Published integration activity</div>
        <div className="steward-dashboard-row-list">
          {state.integration.commits.length ? (
            state.integration.commits.slice(0, 5).map((commit) => (
              <a className="steward-dashboard-row" href={commit.commit_url} key={commit.commit} rel="noreferrer" target="_blank">
                <GitBranch aria-hidden="true" />
                <span>
                  <strong>{commit.title}</strong>
                  <small>{shortSha(commit.commit)} / {relativeTime(commit.updated_at)}</small>
                </span>
                <StewardStatus status={commit.status} />
              </a>
            ))
          ) : integrationTasks.length ? (
            integrationTasks.slice(0, 8).map((task) => (
              <Link className="steward-dashboard-row" href={task.detail_url ?? `/steward/tasks/${task.id}`} key={task.id}>
                <GitBranch aria-hidden="true" />
                <span>
                  <strong>{integrationTaskTitle(task)}</strong>
                  <small>{task.status} / {relativeTime(task.updated_at)}</small>
                </span>
                <StewardStatus status={task.status} />
              </Link>
            ))
          ) : (
            <div className="steward-dashboard-empty">No Integration runs in the mirror window</div>
          )}
        </div>
      </section>
    </div>
  );
}

function StewardAuditTab({ state }: { state: PublicStewardState }) {
  return (
    <section className="steward-dashboard-evidence steward-dashboard-audit" aria-labelledby="steward-audit-heading">
      <PanelTitle icon={<ShieldCheck aria-hidden="true" />} title="Invariant audit" description="Sanitized findings from the local Steward store." />
      <div className="steward-dashboard-evidence-heading" id="steward-audit-heading">Published findings</div>
      {state.audit.length ? (
        <ul className="steward-dashboard-audit-list">
          {state.audit.map((finding, index) => (
            <li key={`${finding}-${index}`}>
              <Circle aria-hidden="true" />
              <span>{finding}</span>
            </li>
          ))}
        </ul>
      ) : (
        <div className="steward-dashboard-empty">No invariant findings were published.</div>
      )}
    </section>
  );
}

function StewardConfigurationTab({ state }: { state: PublicStewardState }) {
  const limits = Object.entries(state.configuration.limits);
  const providers = Object.entries(state.configuration.signal_providers);
  return (
    <section className="steward-dashboard-evidence steward-dashboard-configuration" aria-labelledby="steward-configuration-heading">
      <PanelTitle icon={<Settings2 aria-hidden="true" />} title="Public configuration" description="Only sanitized operating values are included in the mirror." />
      <div className="steward-dashboard-evidence-heading" id="steward-configuration-heading">Operating values</div>
      <dl className="steward-dashboard-config-grid">
        <ConfigFact label="Repository" value={state.configuration.repository} />
        <ConfigFact label="Main branch" value={state.configuration.main_branch} />
        <ConfigFact label="Integration mode" value={state.configuration.integration_mode} machine />
        <ConfigFact label="Local-only" value={state.configuration.local_only ? 'yes' : 'no'} machine />
        <ConfigFact label="Scheduler wait" value={`${state.configuration.scheduler_wait_interval_sec}s`} machine />
        <ConfigFact label="Enabled signals" value={state.configuration.enabled_signals.join(', ') || 'none'} machine />
      </dl>
      <div className="steward-dashboard-config-groups">
        <section>
          <h3>Limits</h3>
          {limits.length ? <ul>{limits.map(([key, value]) => <li key={key}><span>{key}</span><strong className="steward-dashboard-machine">{value ?? '-'}</strong></li>)}</ul> : <p>Not published</p>}
        </section>
        <section>
          <h3>Provider cadence</h3>
          {providers.length ? <ul>{providers.map(([key, value]) => <li key={key}><span>{key}</span><strong className="steward-dashboard-machine">{value.poll_interval_minutes}m</strong></li>)}</ul> : <p>No providers enabled</p>}
        </section>
      </div>
    </section>
  );
}

function ConfigFact({ label, machine = false, value }: { label: string; machine?: boolean; value: string }) {
  return <div><dt>{label}</dt><dd className={machine ? 'steward-dashboard-machine' : undefined}>{value}</dd></div>;
}

function StewardTasksTab({ state }: { state: PublicStewardState }) {
  const userTasks = state.tasks.filter((task) => !isPublicIntegrationTask(task));
  return (
    <div className="steward-dashboard-task-view">
      <section className="steward-dashboard-evidence steward-dashboard-task-table" aria-labelledby="steward-task-queue-heading">
        <PanelTitle icon={<ListChecks aria-hidden="true" />} title="Task Queue" />
        <div className="steward-dashboard-evidence-heading" id="steward-task-queue-heading">Current task evidence</div>
        {state.tasks_truncated && <div className="steward-dashboard-window-notice" role="status">Task window truncated; showing the published task window.</div>}
        <PublicTaskTable repository={state.repository} tasks={userTasks} />
      </section>
      <details className="steward-dashboard-evidence steward-dashboard-task-graph">
        <summary>
          <Route aria-hidden="true" />
          <span><strong>Task Graph</strong><small>Alternate view of the same public task window</small></span>
        </summary>
        <PublicTaskGraph tasks={userTasks} />
      </details>
    </div>
  );
}

function PublicTaskTable({ repository, tasks }: { repository: string; tasks: PublicStewardTask[] }) {
  const pagination = usePublicPagination(tasks);
  if (!tasks.length) return <div className="steward-dashboard-empty">No tasks are currently mirrored.</div>;
  return (
    <>
      <div className="steward-dashboard-table-scroll" data-scroll-region tabIndex={0}>
        <table className="steward-dashboard-table">
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
                <tr className={pagination.start + index === 0 ? 'steward-dashboard-selected-row' : undefined} key={task.id}>
                  <td><Link className="steward-dashboard-task-link" href={task.detail_url ?? `/steward/tasks/${task.id}`}>{task.title}</Link></td>
                  <td><StewardStatus status={task.status} /></td>
                  <td><TaskSpecChip value={task.kind} /></td>
                  <td><TaskSpecChip tone={`priority-${task.priority}`} value={task.priority} /></td>
                  <td><TaskSpecChip tone={`risk-${task.risk}`} value={task.risk} /></td>
                  <td><time className="steward-dashboard-compact-time steward-dashboard-machine" dateTime={task.updated_at} title={shortDate(task.updated_at)}>{compactDate(task.updated_at)}</time></td>
                  <td>{remote ? <CommitLink remote={remote} /> : <span className="steward-dashboard-muted">-</span>}</td>
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
    <div className="steward-dashboard-graph-scroll" data-scroll-region tabIndex={0}>
      <div className="steward-dashboard-graph">
        {TASK_GRAPH_LANES.map((lane) => {
          const laneTasks = tasks
            .filter((task) => lane.statuses.includes(task.status))
            .sort((left, right) => taskUpdatedAtMs(right) - taskUpdatedAtMs(left));
          return (
            <div className="steward-dashboard-graph-lane" key={lane.key}>
              <div className="steward-dashboard-graph-lane-title"><span>{lane.label}</span><strong>{laneTasks.length}</strong></div>
              <div className="steward-dashboard-graph-items">
                {laneTasks.map((task, index) => (
                  <Link className={`steward-dashboard-graph-node ${index === 0 && lane.key === 'completed' ? 'steward-dashboard-graph-node--active' : ''}`} href={task.detail_url ?? `/steward/tasks/${task.id}`} key={task.id} title={task.title}>
                    <div className="steward-dashboard-graph-node-top">
                      <StewardStatus status={task.status} />
                      <time className="steward-dashboard-machine" dateTime={task.updated_at} title={shortDate(task.updated_at)}>Updated {compactDate(task.updated_at)}</time>
                    </div>
                    <strong>{task.title}</strong>
                    <span>Agent <b>{task.worker}</b></span>
                    <div className="steward-dashboard-graph-node-meta">
                      <TaskSpecChip label="Type" value={task.kind} />
                      <TaskSpecChip label="Priority" tone={`priority-${task.priority}`} value={task.priority} />
                      <TaskSpecChip label="Risk" tone={`risk-${task.risk}`} value={task.risk} />
                    </div>
                  </Link>
                ))}
                {!laneTasks.length && <div className="steward-dashboard-graph-empty">{lane.empty}</div>}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function taskUpdatedAtMs(task: PublicStewardTask) {
  const value = Date.parse(task.updated_at);
  return Number.isFinite(value) ? value : 0;
}

function TaskSpecChip({ label, tone = '', value }: { label?: string; tone?: string; value: string }) {
  return <span className={`steward-dashboard-task-chip ${tone}`}>{label && <b>{label}</b>}<span>{value || '-'}</span></span>;
}

function CommitLink({ remote }: { remote: { commit: string; url: string } }) {
  return <a className="steward-dashboard-commit-link" href={remote.url} rel="noreferrer" target="_blank"><ExternalLink aria-hidden="true" /><span className="steward-dashboard-machine">{shortSha(remote.commit)}</span></a>;
}

function taskRemote(task: PublicStewardTask, repository: string): { commit: string; url: string } | null {
  const summaryMatch = task.summary.match(/\b(?:pushed|commit)\s+([a-f0-9]{7,40})\b/i);
  const rawTask = task as unknown as Record<string, unknown>;
  const metadataCommit = typeof rawTask.commit === 'string' ? rawTask.commit : '';
  const metadataUrl = typeof rawTask.commit_url === 'string' ? rawTask.commit_url : '';
  const commit = metadataCommit || summaryMatch?.[1] || '';
  if (!commit) return null;
  return { commit, url: metadataUrl || `https://github.com/${repository}/commit/${commit}` };
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
    <nav className="steward-dashboard-pagination" aria-label={`${itemLabel} pagination`}>
      <span>{start}-{end} of {total}</span>
      <div className="steward-dashboard-pagination-actions">
        <button aria-label={`Previous ${itemLabel} page`} className="steward-dashboard-page-button" disabled={page <= 1} onClick={() => onPageChange(page - 1)} title="Previous page" type="button"><ChevronLeft aria-hidden="true" /></button>
        <PaginationJump itemLabel={itemLabel} onPageChange={onPageChange} page={page} pageCount={pageCount} />
        <button aria-label={`Next ${itemLabel} page`} className="steward-dashboard-page-button" disabled={page >= pageCount} onClick={() => onPageChange(page + 1)} title="Next page" type="button"><ChevronRight aria-hidden="true" /></button>
      </div>
    </nav>
  );
}

function PaginationJump({ itemLabel, onPageChange, page, pageCount }: { itemLabel: string; onPageChange: (page: number) => void; page: number; pageCount: number }) {
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
    <form className="steward-dashboard-pagination-jump" onSubmit={(event) => { event.preventDefault(); submitPage(); }}>
      <label htmlFor={`steward-${itemLabel}-page`}>Page</label>
      <input
        id={`steward-${itemLabel}-page`}
        aria-label={`Go to ${itemLabel} page`}
        className="steward-dashboard-machine"
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
  return { ...pagination, setPage };
}

function StewardSignalsTab({ state }: { state: PublicStewardState }) {
  const [selectedProvider, setSelectedProvider] = useState<string | null>(null);
  const fallbackProvider = state.scheduler.providers[0]?.provider ?? state.signals.items[0]?.provider ?? state.signals.fetches[0]?.provider ?? null;
  const providerNames = new Set(state.scheduler.providers.map((provider) => provider.provider));
  const activeProvider = selectedProvider && providerNames.has(selectedProvider) ? selectedProvider : fallbackProvider;
  const activeProviderMeta = state.scheduler.providers.find((provider) => provider.provider === activeProvider) ?? null;
  const signalItems = activeProvider ? state.signals.items.filter((item) => item.provider === activeProvider) : state.signals.items;
  const recentFetches = (activeProvider ? state.signals.fetches.filter((fetch) => fetch.provider === activeProvider) : state.signals.fetches).slice(0, 8);
  return (
    <section className="steward-dashboard-evidence steward-dashboard-signals" aria-labelledby="steward-signals-heading">
      <PanelTitle title="Signals" description="Select a provider to inspect its signal inbox and fetch history" />
      <div className="steward-dashboard-signals-layout">
        <div className="steward-dashboard-provider-tabs" role="tablist" aria-label="Signal providers" aria-orientation="vertical">
          <SignalColumnHeader title="Providers" description="Poll cadence and provider health" />
          {state.scheduler.providers.map((provider) => (
            <ProviderTab active={provider.provider === activeProvider} key={provider.provider} onSelect={() => setSelectedProvider(provider.provider)} provider={provider} />
          ))}
          {!state.scheduler.providers.length && <div className="steward-dashboard-empty">No signal providers</div>}
        </div>
        <div aria-labelledby={activeProvider ? providerTabId(activeProvider) : undefined} className="steward-dashboard-provider-detail" id="steward-provider-panel" role="tabpanel">
          <div className="steward-dashboard-provider-detail-head">
            <div><strong>{activeProvider ?? 'No provider selected'}</strong><span>{activeProviderMeta ? providerScheduleLabel(activeProviderMeta) : 'Waiting for provider state'}</span></div>
            {activeProviderMeta && <StewardStatus status={activeProviderMeta.last_status ?? 'pending'} />}
          </div>
          <section className="steward-dashboard-signal-section">
            <SignalColumnHeader title="Signal Inbox" description="Current normalized findings for this provider" />
            {signalItems.slice(0, 12).map((item) => <SignalRow item={item} key={item.id} />)}
            {!signalItems.length && <div className="steward-dashboard-empty">No signal items for this provider</div>}
          </section>
          <section className="steward-dashboard-signal-section">
            <SignalColumnHeader title="Fetch History" description="Recent remote polling results for this provider" />
            {recentFetches.map((fetch) => (
              <article className="steward-dashboard-fetch-row" key={fetch.id}>
                <div><strong>{fetch.provider}</strong><time dateTime={fetch.completed_at}>{relativeTime(fetch.completed_at)}</time></div>
                <div className="steward-dashboard-fetch-meta"><StewardStatus status={fetch.status} /><span>{fetch.item_count} items / {fetch.new_item_count} new</span></div>
                <p>{fetch.summary}</p>
                {fetch.error && <small>{fetch.error}</small>}
              </article>
            ))}
            {!recentFetches.length && <div className="steward-dashboard-empty">No recent fetches for this provider</div>}
          </section>
        </div>
      </div>
      <span className="steward-dashboard-visually-hidden" id="steward-signals-heading">Signal evidence</span>
    </section>
  );
}

function SignalColumnHeader({ description, title }: { description: string; title: string }) {
  return <div className="steward-dashboard-column-head"><strong>{title}</strong><span>{description}</span></div>;
}

function DashboardViewTab({ active, icon, label, onSelect, tab, value }: { active: boolean; icon: ReactNode; label: string; onSelect: () => void; tab: StewardMirrorTab; value: string }) {
  return (
    <button aria-controls={`steward-panel-${tab}`} aria-selected={active} className={`steward-dashboard-tab ${active ? 'steward-dashboard-tab--active' : ''}`} id={`steward-tab-${tab}`} onClick={onSelect} onKeyDown={handleTabKeyDown} role="tab" tabIndex={active ? 0 : -1} type="button">
      {icon}<span>{label}</span><strong>{value}</strong>
    </button>
  );
}

function ProviderTab({ active, onSelect, provider }: { active: boolean; onSelect: () => void; provider: PublicStewardProvider }) {
  return (
    <button aria-controls="steward-provider-panel" aria-selected={active} className={`steward-dashboard-provider-tab ${active ? 'steward-dashboard-provider-tab--active' : ''}`} id={providerTabId(provider.provider)} onClick={onSelect} onKeyDown={handleTabKeyDown} role="tab" tabIndex={active ? 0 : -1} type="button">
      <span className="steward-dashboard-provider-tab-main"><span>{provider.provider}</span><StewardStatus status={provider.last_status ?? 'pending'} /></span>
      <small>{providerScheduleLabel(provider)}</small>
    </button>
  );
}

function SignalRow({ item }: { item: PublicStewardSignalItem }) {
  return (
    <article className="steward-dashboard-row steward-dashboard-signal-row">
      <RadioTower aria-hidden="true" />
      <span><strong>{item.title}</strong><small>{item.provider} / {item.kind}</small><span>{item.summary}</span>{item.links.length > 0 && <span className="steward-dashboard-signal-links">{item.links.map((link) => <a href={link.url} key={link.url} rel="noreferrer" target="_blank">{link.label}</a>)}</span>}</span>
      <StewardStatus status={item.status} />
    </article>
  );
}

function StewardStatus({ label, status }: { label?: string; status: string }) {
  const tone = stewardStatusTone(status);
  return (
    <StewardStatusLabel
      className={`steward-dashboard-status steward-dashboard-status--${tone}`}
      label={label}
      status={status}
    />
  );
}

function SchedulerLane({ active, capacity, icon, label, queued }: { active: number; capacity: number; icon: ReactNode; label: string; queued: number }) {
  const slots = Math.max(capacity, active, 1);
  return (
    <div className="steward-dashboard-scheduler-lane">
      <div className="steward-dashboard-scheduler-lane-head">{icon}<strong>{label}</strong></div>
      <div className="steward-dashboard-slot-row" aria-hidden="true">{Array.from({ length: slots }).map((_, index) => <span className={index < active ? 'steward-dashboard-slot steward-dashboard-slot--active' : 'steward-dashboard-slot'} key={`${label}-${index}`} />)}</div>
      <div className="steward-dashboard-scheduler-lane-meta"><span>active <b>{active}</b></span><span>queued <b>{queued}</b></span></div>
    </div>
  );
}

function SummaryFact({ label, machine = false, value }: { label: string; machine?: boolean; value: number | string }) {
  return <div className="steward-dashboard-summary-fact"><dt>{label}</dt><dd className={machine ? 'steward-dashboard-machine' : undefined}>{value === '' ? '-' : value}</dd></div>;
}

function Fact({ label, value }: { label: string; value: string }) {
  return <div className="steward-dashboard-fact"><span>{label}</span><strong>{value || '-'}</strong></div>;
}

function viewValue(tab: StewardMirrorTab, state: PublicStewardState, counts: ReturnType<typeof publicTaskCounts>) {
  if (tab === 'overview') return state.state;
  if (tab === 'tasks') return String(counts.tasks);
  if (tab === 'signals') return String(state.counts.signals);
  if (tab === 'audit') return String(state.audit.length);
  return String(state.configuration.enabled_signals.length);
}

function providerTabId(provider: string) {
  return `steward-provider-tab-${provider.replace(/[^A-Za-z0-9_-]+/g, '-')}`;
}

function isPublicIntegrationTask(task: PublicStewardTask) {
  return task.kind === 'integration' || task.worker === 'integration-manager' || task.source === 'integration';
}

function isActiveTask(task: PublicStewardTask) {
  return ['running', 'reviewing', 'integrating'].includes(task.status);
}

function integrationTaskTitle(task: PublicStewardTask) {
  return task.title.replace(/^Integrate\b/, 'Integration');
}

function publicTaskCounts(tasks: PublicStewardTask[]) {
  const userTasks = tasks.filter((task) => !isPublicIntegrationTask(task));
  return {
    active: userTasks.filter((task) => isActiveTask(task)).length,
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

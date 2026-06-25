"use client";

import Link from "next/link";
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  ChevronDown,
  ChevronLeft,
  ChevronRight,
  Clock3,
  ExternalLink,
  FileText,
  GitBranch,
  Inbox,
  Info,
  LayoutDashboard,
  ListChecks,
  Plus,
  RefreshCw,
  Route,
  Settings,
  ShieldCheck,
  SlidersHorizontal,
  X,
  XCircle,
} from "lucide-react";
import { type FormEvent, type ReactNode, useCallback, useEffect, useMemo, useState } from "react";
import {
  createTask,
  getIntegration,
  getTaskFile,
  getValidationLog,
  getPlannerRun,
  getPlannerRuns,
  getState,
  requestSchedulerTick,
  requestSignalFetch,
  type PlannerRunsPage,
} from "./api";
import { CodeBlock } from "./code-block";
import { TimelineEvent } from "./timeline";
import { TranscriptView } from "./transcript";
import type {
  EventRecord,
  IntegrationDetail,
  IntegrationRun,
  PlannerRunArtifact,
  PlannerRunSummary,
  SignalItem,
  SchedulerProviderState,
  SchedulerWakeup,
  StewardState,
  TaskRecord,
  TaskStatus,
  ValidationResult,
} from "./types";

type ViewKey = "control" | "tasks" | "integration" | "signals" | "configuration";
type StreamState = "connecting" | "live" | "reconnecting";

type CodacySignal = {
  count: number;
  url: string | null;
};

type IntegrationTab = "patch" | "validation" | "commit" | "push";

const LIST_PAGE_SIZE = 10;

const TASK_GRAPH_LANES: Array<{
  empty: string;
  key: string;
  label: string;
  statuses: TaskStatus[];
}> = [
  { key: "queued", label: "Queued", statuses: ["queued"], empty: "No queued tasks" },
  { key: "active", label: "In Progress", statuses: ["running", "reviewing", "integrating"], empty: "No active work" },
  { key: "attention", label: "Needs Attention", statuses: ["blocked", "failed", "cancelled"], empty: "No blocked, failed, or cancelled tasks" },
  { key: "completed", label: "Completed", statuses: ["succeeded", "pushed", "no_changes"], empty: "No completed tasks" },
];

const EMPTY_STATE: StewardState = {
  tasks: [],
  audit: [],
  planned: [],
  projects: [],
  kinds: ["custom"],
  workers: ["custom"],
  signals: {
    schema_version: 2,
    repository: "",
    enabled_signals: [],
    generated_at: "",
    summary: "",
    items: [],
    fetches: [],
  },
  integration: {
    queue: [],
    active: [],
    commits: [],
  },
  signal_inbox: {
    items: [],
    fetch_runs: [],
  },
  scheduler: {
    source_active: 0,
    source_capacity: 0,
    source_queued: 0,
    integration_active: 0,
    integration_queued: 0,
    pending_wakeups: [],
    recent_wakeups: [],
    providers: [],
  },
  config: {
    repo_root: "",
    coquic_home: "",
    steward_home: "",
    state_dir: "",
    worktrees_dir: "",
    transcripts_dir: "",
    logs_dir: "",
    prompts_dir: "",
    patches_dir: "",
    db_path: "",
    config_path: "",
    codex_bin: "",
    codex_bin_resolved: null,
    codex_bin_available: false,
    codex_model: null,
    codex_profile: null,
    codex_sandbox: "",
    integration_mode: "",
    local_only: false,
    git_remote: "",
    main_branch: "",
    github_repository: "",
    enabled_signals: [],
    scheduler_wait_interval_sec: 0,
    limits: {
      max_active_tasks: 0,
      max_main_pushes_per_day: 0,
      worker_timeout_minutes: 0,
      review_timeout_minutes: 0,
      validation_timeout_minutes: 0,
      stale_task_minutes: null,
    },
    signal_providers: {},
  },
};

export default function Dashboard() {
  const [state, setState] = useState<StewardState>(EMPTY_STATE);
  const [selectedId, setSelectedId] = useState<string>("");
  const [plannerRunsPage, setPlannerRunsPage] = useState<PlannerRunsPage>({
    runs: [],
    total: 0,
    limit: LIST_PAGE_SIZE,
    offset: 0,
  });
  const [busy, setBusy] = useState(false);
  const [streamState, setStreamState] = useState<StreamState>("connecting");
  const [loadError, setLoadError] = useState("");
  const [view, setView] = useState<ViewKey>("control");
  const [createOpen, setCreateOpen] = useState(false);
  const userTasks = useMemo(() => state.tasks.filter((task) => !isIntegrationTask(task)), [state.tasks]);
  const selectedTask = useMemo(
    () => userTasks.find((task) => task.spec.id === selectedId) ?? userTasks[0],
    [selectedId, userTasks],
  );

  useEffect(() => {
    void refresh();
    getPlannerRuns({ limit: LIST_PAGE_SIZE, offset: 0 }).then(setPlannerRunsPage);
  }, []);

  useEffect(() => {
    const source = new EventSource("/api/stream");
    source.addEventListener("open", () => setStreamState("live"));
    source.addEventListener("error", () => setStreamState("reconnecting"));
    source.addEventListener("state", (event) => {
      const next = JSON.parse((event as MessageEvent).data) as StewardState;
      setState(next);
      setSelectedId((current) => current || next.tasks.find((task) => !isIntegrationTask(task))?.spec.id || "");
    });
    return () => source.close();
  }, []);

  useEffect(() => {
    if (!createOpen) return;
    function handleKeyDown(event: KeyboardEvent) {
      if (event.key === "Escape") {
        setCreateOpen(false);
      }
    }
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [createOpen]);

  async function refresh() {
    try {
      const next = await getState();
      setState(next);
      setLoadError("");
      setSelectedId((current) => current || next.tasks.find((task) => !isIntegrationTask(task))?.spec.id || "");
    } catch (error) {
      setLoadError(errorMessage(error, "Unable to load Steward state."));
      setStreamState("reconnecting");
    }
  }

  async function loadPlannerRunsPage(page: number) {
    const offset = (page - 1) * LIST_PAGE_SIZE;
    setPlannerRunsPage(await getPlannerRuns({ limit: LIST_PAGE_SIZE, offset }));
  }

  async function handleCreateTask(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const data = new FormData(form);
    setBusy(true);
    try {
      await createTask({
        title: String(data.get("title") || ""),
        prompt: String(data.get("prompt") || ""),
        kind: String(data.get("kind") || "custom"),
        worker: String(data.get("worker") || "custom"),
      });
      form.reset();
      await refresh();
      setCreateOpen(false);
    } finally {
      setBusy(false);
    }
  }

  async function handleWakeScheduler() {
    setBusy(true);
    try {
      await requestSchedulerTick({ plan: true, dispatch: true });
      await refresh();
    } finally {
      setBusy(false);
    }
  }

  async function handleFetchSignals(providers: string[]) {
    setBusy(true);
    try {
      await requestSignalFetch(providers);
      await refresh();
    } finally {
      setBusy(false);
    }
  }

  const counts = {
    ...countTasks(state.tasks),
    signals: state.signal_inbox?.items.length ?? 0,
  };

  return (
    <main className="app-frame">
      <aside className="sidebar">
        <div className="sidebar-brand">
          <div className="brand-mark">CQ</div>
          <div className="brand-copy">
            <div className="brand-title">
              <h1>CoQUIC Steward</h1>
            </div>
            <ProjectSelector counts={counts} state={state} streamState={streamState} />
          </div>
        </div>
        <SectionNav active={view} counts={counts} onSelect={setView} />
        <div className="sidebar-actions">
          <div>
            <button className="icon-button secondary" onClick={refresh} type="button" title="Refresh state" aria-label="Refresh state">
              <RefreshCw size={16} />
            </button>
            <button className="icon-button" onClick={() => setCreateOpen(true)} type="button" title="Create task" aria-label="Create task">
              <Plus size={16} />
            </button>
          </div>
        </div>
      </aside>
      <section className="app-shell">
        <header className="topbar">
          <div className="top-title">
            <h1>{viewTitle(view)}</h1>
          </div>
        </header>

        <DashboardView
          counts={counts}
          loadError={loadError}
          onRefresh={refresh}
          onRequestFetch={handleFetchSignals}
          onWakeScheduler={handleWakeScheduler}
          onPlannerPageChange={loadPlannerRunsPage}
          plannerRunsPage={plannerRunsPage}
          selectedTask={selectedTask}
          state={state}
          view={view}
          busy={busy}
        />
      </section>
      {createOpen && (
        <CreateTaskModal
          busy={busy}
          kinds={state.kinds}
          onClose={() => setCreateOpen(false)}
          onCreateTask={handleCreateTask}
          workers={state.workers}
        />
      )}
    </main>
  );
}

function Metric({ icon, label, value }: { icon: ReactNode; label: string; value: string | number }) {
  return (
    <div className="metric">
      <div className="metric-icon">{icon}</div>
      <div>
        <b>{value}</b>
        <span>{label}</span>
      </div>
    </div>
  );
}

function PanelTitle({ icon, title }: { icon: ReactNode; title: string }) {
  return (
    <div className="panel-title">
      {icon}
      <h2>{title}</h2>
    </div>
  );
}

function ProjectSelector({
  counts,
  state,
  streamState,
}: {
  counts: ReturnType<typeof countTasks>;
  state: StewardState;
  streamState: StreamState;
}) {
  const activeLabel = state.config.github_repository || state.signals.repository || "Loading project";
  const stateProjects = state.projects ?? [];
  const projects = stateProjects.length
    ? stateProjects
    : [
        {
          id: projectId(state.config.state_dir),
          label: activeLabel,
          state_dir: state.config.state_dir,
          active: true,
          task_count: counts.total,
        },
      ];
  return (
    <div className="project-switcher">
      <details className="project-menu">
        <summary aria-label="Select project">
          <span>{activeLabel}</span>
          <ChevronDown size={13} />
        </summary>
        <div className="project-menu-popover">
          {projects.map((project) => (
            <button className={project.active ? "active" : ""} disabled={!project.active} key={project.id} type="button">
              <span>{project.label}</span>
              <code>{project.id}</code>
              <b>{project.active ? "current" : `${project.task_count} tasks`}</b>
            </button>
          ))}
        </div>
      </details>
      <span
        className={`stream-dot ${streamState}`}
        aria-label={`Stream ${streamState}`}
        title={`Stream ${streamState}`}
      />
      <div className="project-info" tabIndex={0} aria-label="Project information">
        <Info size={14} />
        <div className="project-info-popover" role="tooltip">
          <KeyValue label="Tasks" value={String(counts.total)} />
          <KeyValue label="Active" value={String(counts.active)} />
          <KeyValue label="Queued" value={String(counts.queued)} />
          <KeyValue label="Signals" value={String(state.config.enabled_signals.length)} />
          <KeyValue label="State" value={projectId(state.config.state_dir)} />
          <KeyValue label="Root" value={state.config.repo_root || "-"} />
        </div>
      </div>
    </div>
  );
}

function SectionNav({
  active,
  counts,
  onSelect,
}: {
  active: ViewKey;
  counts: ReturnType<typeof countTasks>;
  onSelect: (view: ViewKey) => void;
}) {
  const projectItems: Array<{ icon: ReactNode; key: ViewKey; label: string; meta?: string | number }> = [
    { icon: <LayoutDashboard size={17} />, key: "control", label: "Control Loop" },
    { icon: <ListChecks size={17} />, key: "tasks", label: "Tasks", meta: counts.total },
    { icon: <GitBranch size={17} />, key: "integration", label: "Integration", meta: counts.integration },
    { icon: <Inbox size={17} />, key: "signals", label: "Signals", meta: counts.signals },
    { icon: <Settings size={17} />, key: "configuration", label: "Configuration" },
  ];
  return (
    <nav className="sidebar-nav" aria-label="Steward sections">
      {projectItems.map((item) => (
        <button
          className={active === item.key ? "active" : ""}
          key={item.key}
          onClick={() => onSelect(item.key)}
          type="button"
        >
          {item.icon}
          <span>{item.label}</span>
          {item.meta !== undefined && <b>{item.meta}</b>}
        </button>
      ))}
    </nav>
  );
}

function DashboardView({
  busy,
  counts,
  loadError,
  onPlannerPageChange,
  onRequestFetch,
  onRefresh,
  onWakeScheduler,
  plannerRunsPage,
  selectedTask,
  state,
  view,
}: {
  busy: boolean;
  counts: ReturnType<typeof countTasks>;
  loadError: string;
  onPlannerPageChange: (page: number) => Promise<void>;
  onRequestFetch: (providers: string[]) => Promise<void>;
  onRefresh: () => Promise<void>;
  onWakeScheduler: () => Promise<void>;
  plannerRunsPage: PlannerRunsPage;
  selectedTask?: TaskRecord;
  state: StewardState;
  view: ViewKey;
}) {
  const userTasks = state.tasks.filter((task) => !isIntegrationTask(task));
  const alert = loadError ? <StateLoadAlert message={loadError} onRefresh={onRefresh} /> : null;
  if (view === "tasks") {
    return (
      <section className="main-grid">
        {alert}
        <div className="left-stack">
          <TaskGraphPanel selectedId={selectedTask?.spec.id || ""} tasks={userTasks} />
          <TaskQueuePanel
            githubRepository={state.config.github_repository || state.signals.repository}
            selectedId={selectedTask?.spec.id || ""}
            tasks={userTasks}
          />
        </div>
      </section>
    );
  }
  if (view === "integration") {
    return (
      <>
        {alert}
        <IntegrationPanel
          items={state.integration ?? { queue: [], active: [], runs: [], commits: [] }}
          state={state}
        />
      </>
    );
  }
  if (view === "signals") {
    return (
      <>
        {alert}
        <SignalsPanel
          busy={busy}
          onRequestFetch={onRequestFetch}
          state={state}
          tasks={userTasks}
        />
      </>
    );
  }
  if (view === "configuration") {
    return (
      <>
        {alert}
        <ConfigurationPanel state={state} />
      </>
    );
  }
  return (
    <>
      {alert}
      <section className="metrics">
        <Metric icon={<Activity size={18} />} label="Active" value={counts.active} />
        <Metric icon={<Clock3 size={18} />} label="Queued" value={counts.queued} />
        <Metric icon={<CheckCircle2 size={18} />} label="Terminal" value={counts.terminal} />
        <Metric icon={<GitBranch size={18} />} label="Integration" value={integrationLabel(state)} />
      </section>
      <section className="control-grid">
        <div className="left-stack">
          <SchedulerPanel
            busy={busy}
            onRequestFetch={onRequestFetch}
            onWakeScheduler={onWakeScheduler}
            state={state}
          />
          <PlannerTranscriptPanel onPageChange={onPlannerPageChange} page={plannerRunsPage} />
        </div>
      </section>
    </>
  );
}

function StateLoadAlert({
  message,
  onRefresh,
}: {
  message: string;
  onRefresh: () => Promise<void>;
}) {
  return (
    <div className="inline-alert">
      <span>{message}</span>
      <button className="button-inline" onClick={() => void onRefresh()} type="button">
        Retry
      </button>
    </div>
  );
}

function usePagination<T>(items: T[], pageSize: number = LIST_PAGE_SIZE) {
  const [page, setPage] = useState(1);
  const pageCount = Math.max(1, Math.ceil(items.length / pageSize));
  const safePage = Math.min(page, pageCount);
  const start = (safePage - 1) * pageSize;
  const pageItems = useMemo(() => items.slice(start, start + pageSize), [items, pageSize, start]);
  const setSafePage = useCallback((nextPage: number) => {
    setPage(Math.max(1, Math.min(nextPage, pageCount)));
  }, [pageCount]);
  return {
    page: safePage,
    pageCount,
    pageItems,
    pageSize,
    setPage: setSafePage,
    start,
  };
}

function PaginationControls({
  fetchedTotal,
  itemLabel,
  page,
  pageCount,
  pageSize,
  total,
  onPageChange,
}: {
  fetchedTotal?: number;
  itemLabel: string;
  page: number;
  pageCount: number;
  pageSize: number;
  total: number;
  onPageChange: (page: number) => void;
}) {
  if (total <= pageSize && (fetchedTotal ?? total) <= pageSize) return null;
  const start = total ? (page - 1) * pageSize + 1 : 0;
  const end = Math.min(page * pageSize, total);
  const fetchedSuffix = fetchedTotal !== undefined && fetchedTotal > total ? ` (${fetchedTotal} total)` : "";
  return (
    <nav className="pagination-bar" aria-label={`${itemLabel} pagination`}>
      <span className="pagination-range">
        {start}-{end} of {total}{fetchedSuffix}
      </span>
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
        <PaginationJump
          key={page}
          itemLabel={itemLabel}
          onPageChange={onPageChange}
          page={page}
          pageCount={pageCount}
        />
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

function TaskQueuePanel({
  selectedId,
  tasks,
  githubRepository,
}: {
  selectedId: string;
  tasks: TaskRecord[];
  githubRepository: string;
}) {
  return (
    <section className="panel">
      <PanelTitle icon={<ListChecks size={17} />} title="Task Queue" />
      <TaskTable githubRepository={githubRepository} selectedId={selectedId} tasks={tasks} />
    </section>
  );
}

function TaskGraphPanel({
  selectedId,
  tasks,
}: {
  selectedId: string;
  tasks: TaskRecord[];
}) {
  return (
    <section className="panel">
      <PanelTitle icon={<Route size={17} />} title="Task Graph" />
      <TaskGraph tasks={tasks} selectedId={selectedId} />
    </section>
  );
}

function PlannerTranscriptPanel({
  onPageChange,
  page,
}: {
  onPageChange: (page: number) => Promise<void>;
  page: PlannerRunsPage;
}) {
  const currentPage = Math.floor(page.offset / page.limit) + 1;
  const pageCount = Math.max(1, Math.ceil(page.total / page.limit));
  const total = page.total;
  return (
    <section className="panel">
      <PanelTitle icon={<FileText size={17} />} title="Planner Iterations" />
      {page.runs.length ? (
        <>
          <div className="planner-run-list">
            {page.runs.map((run, index) => {
              const globalIndex = page.offset + index;
              return (
                <PlannerRunCard
                  index={globalIndex}
                  key={run.run_id}
                  run={run}
                  turn={total - globalIndex}
                />
              );
            })}
          </div>
          <PaginationControls
            itemLabel="planner iterations"
            onPageChange={(nextPage) => void onPageChange(nextPage)}
            page={currentPage}
            pageCount={pageCount}
            pageSize={page.limit}
            total={total}
          />
        </>
      ) : (
        <div className="empty-state">No planner run has been captured yet.</div>
      )}
    </section>
  );
}

function PlannerRunCard({
  index,
  run,
  turn,
}: {
  index: number;
  run: PlannerRunSummary;
  turn: number;
}) {
  const [artifact, setArtifact] = useState<PlannerRunArtifact | null>(null);
  const [open, setOpen] = useState(index === 0);
  useEffect(() => {
    let cancelled = false;
    if (!open || artifact) return;
    getPlannerRun(run.run_id).then((next) => {
      if (!cancelled) setArtifact(next);
    });
    return () => {
      cancelled = true;
    };
  }, [artifact, open, run.run_id]);
  return (
    <details
      className="planner-run-card"
      onToggle={(event) => setOpen(event.currentTarget.open)}
      open={open}
    >
      <summary>
        <div>
          <span className="mono">turn {turn}</span>
          <h3>{run.run_id}</h3>
        </div>
        <div className="planner-run-meta">
          <span>{formatBytes(run.transcript_bytes)}</span>
          {run.updated_at && <time className="mono muted" dateTime={run.updated_at}>{shortDate(run.updated_at)}</time>}
        </div>
      </summary>
      {artifact ? (
        <TranscriptView
          diagnostics={artifact.diagnostics}
          prompt={artifact.prompt}
          taskId={artifact.run_id}
          text={artifact.transcript}
        />
      ) : (
        <div className="empty-state">Loading planner transcript.</div>
      )}
    </details>
  );
}

function CreateTaskModal({
  busy,
  kinds,
  onClose,
  onCreateTask,
  workers,
}: {
  busy: boolean;
  kinds: string[];
  onClose: () => void;
  onCreateTask: (event: FormEvent<HTMLFormElement>) => void;
  workers: string[];
}) {
  return (
    <section className="modal-overlay" role="dialog" aria-modal="true" aria-labelledby="create-task-title">
      <button className="modal-backdrop" onClick={onClose} type="button" aria-label="Close create task" />
      <div className="create-modal">
        <header className="modal-head">
          <div className="modal-title">
            <Plus size={17} />
            <h2 id="create-task-title">Create Task</h2>
          </div>
          <button className="icon-button secondary" onClick={onClose} type="button" title="Close create task" aria-label="Close create task">
            <X size={17} />
          </button>
        </header>
        <form className="create-form" onSubmit={onCreateTask}>
          <label>
            Title
            <input name="title" required placeholder="Debug failed workflow" autoFocus />
          </label>
          <div className="two-col">
            <label>
              Kind
              <select name="kind">{kinds.map((kind) => <option key={kind}>{kind}</option>)}</select>
            </label>
            <label>
              Worker
              <select name="worker">{workers.map((worker) => <option key={worker}>{worker}</option>)}</select>
            </label>
          </div>
          <label>
            Prompt
            <textarea name="prompt" required placeholder="Scope the task precisely." />
          </label>
          <div className="modal-actions">
            <button className="secondary" onClick={onClose} type="button">Cancel</button>
            <button disabled={busy} type="submit">
              Enqueue
            </button>
          </div>
        </form>
      </div>
    </section>
  );
}

function SchedulerPanel({
  busy,
  onRequestFetch,
  onWakeScheduler,
  state,
}: {
  busy: boolean;
  onRequestFetch: (providers: string[]) => Promise<void>;
  onWakeScheduler: () => Promise<void>;
  state: StewardState;
}) {
  const scheduler = schedulerState(state);
  const providerNames = scheduler.providers.map((provider) => provider.provider);
  return (
    <section className="panel scheduler-panel">
      <div className="scheduler-head">
        <PanelTitle icon={<Activity size={17} />} title="Scheduler" />
        <div className="scheduler-actions">
          <button
            className="button-link secondary"
            disabled={busy}
            onClick={() => void onWakeScheduler()}
            type="button"
          >
            <RefreshCw size={14} />
            <span>Wake</span>
          </button>
          <button
            className="button-link secondary"
            disabled={busy || providerNames.length === 0}
            onClick={() => void onRequestFetch(providerNames)}
            type="button"
          >
            <Inbox size={14} />
            <span>Fetch All</span>
          </button>
        </div>
      </div>
      <div className="scheduler-lanes">
        <SchedulerLane
          active={scheduler.source_active}
          capacity={scheduler.source_active + scheduler.source_capacity}
          icon={<ListChecks size={15} />}
          label="Source tasks"
          queued={scheduler.source_queued}
        />
        <SchedulerLane
          active={scheduler.integration_active}
          capacity={1}
          icon={<GitBranch size={15} />}
          label="Integration lane"
          queued={scheduler.integration_queued}
        />
      </div>
      <div className="scheduler-grid">
        <div className="scheduler-column">
          <h3 className="section-subtitle">Providers</h3>
          <ProviderSchedule
            busy={busy}
            onRequestFetch={onRequestFetch}
            providers={scheduler.providers}
          />
        </div>
        <div className="scheduler-column">
          <h3 className="section-subtitle">Wakeups</h3>
          <WakeupList wakeups={scheduler.pending_wakeups.length ? scheduler.pending_wakeups : scheduler.recent_wakeups} />
        </div>
      </div>
    </section>
  );
}

function SchedulerLane({
  active,
  capacity,
  icon,
  label,
  queued,
}: {
  active: number;
  capacity: number;
  icon: ReactNode;
  label: string;
  queued: number;
}) {
  const slots = Math.max(capacity, active, 1);
  return (
    <div className="scheduler-lane">
      <div className="scheduler-lane-head">
        {icon}
        <span>{label}</span>
      </div>
      <div className="slot-row" aria-label={`${label}: ${active} active of ${slots}`}>
        {Array.from({ length: slots }, (_, index) => (
          <span className={index < active ? "slot active" : "slot"} key={index} />
        ))}
      </div>
      <div className="scheduler-lane-meta">
        <b>{active}/{slots}</b>
        <span>{queued} queued</span>
      </div>
    </div>
  );
}

function ProviderSchedule({
  busy,
  onRequestFetch,
  providers,
}: {
  busy: boolean;
  onRequestFetch: (providers: string[]) => Promise<void>;
  providers: SchedulerProviderState[];
}) {
  if (!providers.length) return <div className="empty-state compact">No signal providers are enabled.</div>;
  return (
    <div className="provider-schedule">
      {providers.map((provider) => (
        <article className={`provider-row ${provider.due ? "due" : ""}`} key={provider.provider}>
          <div>
            <div className="signal-card-head">
              <span className="provider-pill">{provider.provider}</span>
              <StatusTextPill status={provider.last_status || (provider.due ? "due" : "scheduled")} />
            </div>
            <p>{providerStatusText(provider)}</p>
            {provider.last_error && <p className="error-text">{provider.last_error}</p>}
          </div>
          <button
            className="icon-button secondary"
            disabled={busy}
            onClick={() => void onRequestFetch([provider.provider])}
            title={`Fetch ${provider.provider}`}
            type="button"
          >
            <RefreshCw size={14} />
          </button>
        </article>
      ))}
    </div>
  );
}

function WakeupList({ wakeups }: { wakeups: SchedulerWakeup[] }) {
  if (!wakeups.length) return <div className="empty-state compact">No scheduler wakeups recorded yet.</div>;
  return (
    <div className="wakeup-list">
      {wakeups.slice(0, 8).map((wakeup) => (
        <article className={`wakeup-row ${wakeup.status}`} key={wakeup.id}>
          <div className="wakeup-main">
            <div className="wakeup-head">
              <h3>{wakeup.reason}</h3>
              <time className="mono muted" dateTime={wakeup.created_at}>{compactDate(wakeup.created_at)}</time>
            </div>
            <WakeupDetails wakeup={wakeup} />
          </div>
        </article>
      ))}
    </div>
  );
}

function WakeupDetails({ wakeup }: { wakeup: SchedulerWakeup }) {
  const details = wakeupDetailEntries(wakeup);
  if (!details.length) return <p className="muted">No payload.</p>;
  return (
    <dl className="wakeup-details">
      {details.map((detail) => (
        <div key={detail.label}>
          <dt>{detail.label}</dt>
          <dd className={detail.mono ? "mono" : ""}>{detail.value}</dd>
        </div>
      ))}
    </dl>
  );
}

function SignalsPanel({
  busy,
  onRequestFetch,
  state,
  tasks,
}: {
  busy: boolean;
  onRequestFetch: (providers: string[]) => Promise<void>;
  state: StewardState;
  tasks: TaskRecord[];
}) {
  const items = state.signal_inbox?.items ?? [];
  const fetchRuns = state.signal_inbox?.fetch_runs ?? [];
  const repository = state.config.github_repository || state.signals.repository;
  const [detailId, setDetailId] = useState("");
  const selected = items.find((item) => item.id === detailId) ?? null;
  const pendingItems = items.filter((item) => item.status === "pending");
  const consumedItems = items.filter((item) => item.status !== "pending");
  return (
    <div className="signals-page">
      <section className="metrics">
        <Metric icon={<Inbox size={18} />} label="Signal Items" value={items.length} />
        <Metric icon={<Clock3 size={18} />} label="Pending" value={pendingItems.length} />
        <Metric icon={<CheckCircle2 size={18} />} label="Consumed" value={consumedItems.length} />
        <Metric icon={<AlertTriangle size={18} />} label="Fetch Errors" value={fetchRuns.filter((run) => run.status === "error").length} />
      </section>
      <section className="signals-stack">
        <FoldablePanel defaultOpen icon={<Activity size={17} />} meta={schedulerState(state).providers.length} title="Provider Schedule">
          <ProviderSchedule
            busy={busy}
            onRequestFetch={onRequestFetch}
            providers={schedulerState(state).providers}
          />
        </FoldablePanel>
        <FoldablePanel defaultOpen icon={<Inbox size={17} />} meta={pendingItems.length} title="Pending Signals">
          <SignalInboxList
            emptyText="No pending signals."
            itemLabel="pending signals"
            items={pendingItems}
            onSelect={setDetailId}
            repository={repository}
            selectedId={selected?.id || ""}
          />
        </FoldablePanel>
        <FoldablePanel defaultOpen={false} icon={<CheckCircle2 size={17} />} meta={consumedItems.length} title="Consumed Signals">
          <SignalInboxList
            emptyText="No consumed signals."
            itemLabel="consumed signals"
            items={consumedItems}
            onSelect={setDetailId}
            repository={repository}
            selectedId={selected?.id || ""}
          />
        </FoldablePanel>
        <FoldablePanel defaultOpen={false} icon={<Activity size={17} />} meta={fetchRuns.length} title="Fetch History">
          <SignalFetchHistory repository={repository} runs={fetchRuns} />
        </FoldablePanel>
      </section>
      {selected && (
        <SignalItemModal
          item={selected}
          onClose={() => setDetailId("")}
          repository={repository}
          tasks={tasks}
        />
      )}
    </div>
  );
}

function ConfigurationPanel({ state }: { state: StewardState }) {
  const config = state.config;
  const limits = config.limits;
  const providers = Object.entries(config.signal_providers ?? {}).sort(([left], [right]) => left.localeCompare(right));
  const codexStatus = config.codex_bin_available ? "ok" : "error";
  const codexLabel = config.codex_bin_available ? "available" : "missing";
  return (
    <div className="configuration-page">
      <section className="metrics">
        <Metric icon={<ShieldCheck size={18} />} label="Codex" value={codexLabel} />
        <Metric icon={<SlidersHorizontal size={18} />} label="Sandbox" value={config.codex_sandbox || "-"} />
        <Metric icon={<Inbox size={18} />} label="Providers" value={config.enabled_signals.length} />
        <Metric icon={<ListChecks size={18} />} label="Task Capacity" value={limits?.max_active_tasks ?? "-"} />
      </section>
      <section className="configuration-grid">
        <section className="panel config-panel">
          <PanelTitle icon={<ShieldCheck size={17} />} title="Execution" />
          <div className="config-summary-row">
            <div>
              <span className="section-subtitle">Codex executable</span>
              <h3>{config.codex_bin || "codex"}</h3>
            </div>
            <StatusTextPill status={codexStatus} />
          </div>
          {!config.codex_bin_available && (
            <div className="inline-alert compact">
              <span>Codex is not available to the daemon process. Set an absolute codex_bin in steward.toml or launch with a PATH that contains codex.</span>
            </div>
          )}
          <div className="config-kv-list">
            <KeyValue label="Resolved" value={config.codex_bin_resolved || "-"} />
            <KeyValue label="Sandbox" value={config.codex_sandbox || "-"} />
            <KeyValue label="Model" value={config.codex_model || "default"} />
            <KeyValue label="Profile" value={config.codex_profile || "default"} />
            <KeyValue label="Steward runner" value="host process" />
          </div>
        </section>

        <section className="panel config-panel">
          <PanelTitle icon={<GitBranch size={17} />} title="Project" />
          <div className="config-kv-list">
            <KeyValue label="Repository" value={config.github_repository || "-"} />
            <KeyValue label="Root" value={config.repo_root || "-"} />
            <KeyValue label="Main branch" value={config.main_branch || "-"} />
            <KeyValue label="Remote" value={config.git_remote || "-"} />
            <KeyValue label="Integration" value={integrationLabel(state)} />
          </div>
        </section>

        <section className="panel config-panel wide">
          <PanelTitle icon={<FileText size={17} />} title="State Paths" />
          <div className="config-path-grid">
            <KeyValue label="Config file" value={config.config_path || "-"} />
            <KeyValue label="COQUIC_HOME" value={config.coquic_home || "-"} />
            <KeyValue label="Steward home" value={config.steward_home || "-"} />
            <KeyValue label="State" value={config.state_dir || "-"} />
            <KeyValue label="Database" value={config.db_path || "-"} />
            <KeyValue label="Worktrees" value={config.worktrees_dir || "-"} />
            <KeyValue label="Transcripts" value={config.transcripts_dir || "-"} />
            <KeyValue label="Logs" value={config.logs_dir || "-"} />
            <KeyValue label="Prompts" value={config.prompts_dir || "-"} />
            <KeyValue label="Patches" value={config.patches_dir || "-"} />
          </div>
        </section>

        <section className="panel config-panel">
          <PanelTitle icon={<Activity size={17} />} title="Scheduler Limits" />
          <div className="config-kv-list">
            <KeyValue label="Wait interval" value={`${config.scheduler_wait_interval_sec ?? 0}s`} />
            <KeyValue label="Active tasks" value={String(limits?.max_active_tasks ?? "-")} />
            <KeyValue label="Main pushes/day" value={String(limits?.max_main_pushes_per_day ?? "-")} />
            <KeyValue label="Worker timeout" value={formatOptionalMinutes(limits?.worker_timeout_minutes)} />
            <KeyValue label="Review timeout" value={formatOptionalMinutes(limits?.review_timeout_minutes)} />
            <KeyValue label="Validation timeout" value={formatOptionalMinutes(limits?.validation_timeout_minutes)} />
            <KeyValue label="Stale task" value={limits?.stale_task_minutes == null ? "derived" : formatMinutes(limits.stale_task_minutes)} />
          </div>
        </section>

        <section className="panel config-panel">
          <PanelTitle icon={<Inbox size={17} />} title="Signal Providers" />
          {providers.length ? (
            <div className="config-provider-list">
              {providers.map(([name, provider]) => (
                <article className="config-provider-row" key={name}>
                  <div className="signal-card-head">
                    <span className="provider-pill">{name}</span>
                    <StatusTextPill status={config.enabled_signals.includes(name) ? "ok" : "disabled"} />
                  </div>
                  <dl>
                    <div><dt>poll</dt><dd>{formatMinutes(provider.poll_interval_minutes)}</dd></div>
                    <div><dt>retry</dt><dd>{formatMinutes(provider.error_retry_minutes)}</dd></div>
                    <div><dt>suppress</dt><dd>{provider.suppression_hours}h</dd></div>
                    <div><dt>max</dt><dd>{provider.max_items}</dd></div>
                  </dl>
                </article>
              ))}
            </div>
          ) : (
            <div className="empty-state compact">No signal providers are configured.</div>
          )}
        </section>
      </section>
    </div>
  );
}

function SignalInboxList({
  emptyText,
  itemLabel,
  items,
  onSelect,
  repository,
  selectedId,
}: {
  emptyText: string;
  itemLabel: string;
  items: SignalItem[];
  onSelect: (id: string) => void;
  repository: string;
  selectedId: string;
}) {
  const pagination = usePagination(items);
  if (!items.length) return <div className="empty-state">{emptyText}</div>;
  return (
    <>
      <div className="signal-list">
        {pagination.pageItems.map((item) => {
          const codacy = codacySignal(item.summary || "", repository || repositoryFromPayload(item.payload || {}));
          const link = primarySignalLink(item) || (codacy?.url ? { label: "Open Codacy", url: codacy.url } : null);
          return (
            <article className={`signal-card ${item.status} ${item.id === selectedId ? "active" : ""}`} key={item.id}>
              <button
                className="signal-card-select"
                onClick={() => onSelect(item.id)}
                type="button"
              >
                <SignalCardContent item={item} />
              </button>
              <div className="signal-card-actions">
                <code>{item.id}</code>
                {link?.url && (
                  <a className="button-link signal-link" href={link.url} rel="noreferrer" target="_blank">
                    <ExternalLink size={13} />
                    <span>{link.label}</span>
                  </a>
                )}
              </div>
            </article>
          );
        })}
      </div>
      <PaginationControls
        itemLabel={itemLabel}
        onPageChange={pagination.setPage}
        page={pagination.page}
        pageCount={pagination.pageCount}
        pageSize={pagination.pageSize}
        total={items.length}
      />
    </>
  );
}

function SignalCardContent({
  item,
}: {
  item: SignalItem;
}) {
  return (
    <div className="signal-card-main">
      <div className="signal-card-head">
        <span className="provider-pill">{item.provider}</span>
        <time className="mono muted" dateTime={item.created_at}>{shortDate(item.created_at)}</time>
      </div>
      <h3>{item.title}</h3>
      <SignalSummary item={item} />
    </div>
  );
}

function SignalSummary({
  item,
}: {
  item: SignalItem;
}) {
  const codacy = codacySignal(item.summary);
  if (codacy) {
    return (
      <div className="signal-summary codacy">
        <div className="signal-count">
          <b>{codacy.count}</b>
          <span>open finding{codacy.count === 1 ? "" : "s"}</span>
        </div>
      </div>
    );
  }
  const location = signalLocationLabel(item);
  return (
    <p>
      {item.summary || item.kind}
      {location ? <span className="mono"> {location}</span> : null}
    </p>
  );
}

function FoldablePanel({
  children,
  defaultOpen,
  icon,
  meta,
  title,
}: {
  children: ReactNode;
  defaultOpen: boolean;
  icon: ReactNode;
  meta?: number;
  title: string;
}) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <section className={`panel fold-panel ${open ? "open" : ""}`}>
      <button aria-expanded={open} className="fold-head" onClick={() => setOpen(!open)} type="button">
        <div className="fold-title">
          <ChevronDown size={15} />
          {icon}
          <h2>{title}</h2>
        </div>
        {meta !== undefined && <b>{meta}</b>}
      </button>
      {open && <div className="fold-body">{children}</div>}
    </section>
  );
}

function SignalItemModal({
  item,
  onClose,
  repository,
  tasks,
}: {
  item: SignalItem;
  onClose: () => void;
  repository: string;
  tasks: TaskRecord[];
}) {
  return (
    <section className="modal-overlay" role="dialog" aria-modal="true" aria-labelledby="signal-detail-title">
      <button className="modal-backdrop" onClick={onClose} type="button" aria-label="Close signal detail" />
      <div className="signal-detail-modal">
        <header className="modal-head">
          <div className="modal-title">
            <Info size={17} />
            <h2 id="signal-detail-title">Signal Detail</h2>
          </div>
          <button className="icon-button secondary" onClick={onClose} type="button" title="Close signal detail" aria-label="Close signal detail">
            <X size={16} />
          </button>
        </header>
        <SignalItemDetail item={item} repository={repository} tasks={tasks} />
      </div>
    </section>
  );
}

function SignalItemDetail({
  item,
  repository,
  tasks,
}: {
  item: SignalItem | null;
  repository: string;
  tasks: TaskRecord[];
}) {
  if (!item) return <div className="empty-state">Select a signal item to inspect its payload.</div>;
  const relatedTasks = tasks.filter((task) => taskMatchesSignal(task, item));
  const location = signalLocationLabel(item);
  return (
    <div className="signal-detail">
      <div className="signal-detail-head">
        <div>
          <StatusTextPill status={item.status} />
          <h3>{item.title}</h3>
          <p>{repository || item.provider}</p>
        </div>
      </div>
      <div className="signal-facts">
        <KeyValue label="Provider" value={item.provider} />
        <KeyValue label="Kind" value={item.kind} />
        <KeyValue label="Severity" value={item.severity || "-"} />
        <KeyValue label="Location" value={location || "-"} />
        <KeyValue label="Fingerprint" value={item.fingerprint} />
        <KeyValue label="Fetch" value={item.source_fetch_id || "-"} />
        <KeyValue label="Planner" value={item.planner_run_id || "-"} />
      </div>
      <div className="signal-related">
        <h3 className="section-subtitle">Related Tasks</h3>
        {relatedTasks.length ? (
          <div className="signal-related-list">
            {relatedTasks.map((task) => {
              const display = taskDisplay(task);
              return (
                <Link className="signal-related-task" href={taskHref(task.spec.id)} key={task.spec.id}>
                  <StatusTextPill status={task.status} />
                  <span>{display.title}</span>
                  <TaskSpecChip label="Type" value={display.kind} />
                </Link>
              );
            })}
          </div>
        ) : (
          <div className="empty-state compact">No user-facing task is linked to this signal yet.</div>
        )}
      </div>
      <h3 className="section-subtitle">Payload</h3>
      <CodeBlock compact language="json" text={JSON.stringify(item.payload, null, 2)} title="Payload JSON" />
    </div>
  );
}

function SignalFetchHistory({
  repository,
  runs,
}: {
  repository: string;
  runs: NonNullable<StewardState["signal_inbox"]>["fetch_runs"];
}) {
  if (!runs.length) return <div className="empty-state">No signal fetch runs have been recorded yet.</div>;
  return (
    <div className="fetch-list">
      {runs.slice(0, 16).map((run) => {
        const codacy = codacySignal(run.summary, repository);
        return (
          <article className={`fetch-card ${run.status}`} key={run.id}>
            <div>
              <div className="signal-card-head">
                <StatusTextPill status={run.status} />
                <span className="provider-pill">{run.provider}</span>
              </div>
              {run.error ? (
                <p>{run.error}</p>
              ) : codacy ? (
                <div className="signal-summary codacy compact">
                  <div className="signal-count">
                    <b>{codacy.count}</b>
                    <span>open finding{codacy.count === 1 ? "" : "s"}</span>
                  </div>
                  {codacy.url && (
                    <a className="button-link signal-link" href={codacy.url} rel="noreferrer" target="_blank">
                      <ExternalLink size={13} />
                      <span>Open Codacy</span>
                    </a>
                  )}
                </div>
              ) : (
                <p>{run.summary || `${run.new_item_count} new of ${run.item_count} item(s)`}</p>
              )}
            </div>
            <time className="mono muted" dateTime={run.completed_at}>{shortDate(run.completed_at)}</time>
          </article>
        );
      })}
    </div>
  );
}

function IntegrationPanel({
  items,
  state,
}: {
  items: StewardState["integration"];
  state: StewardState;
}) {
  const runs = integrationRuns(items, state.tasks);
  const [selectedRunId, setSelectedRunId] = useState("");
  function toggleRun(runId: string) {
    setSelectedRunId((current) => current === runId ? "" : runId);
  }
  return (
    <div className="integration-page">
      <section className="metrics">
        <Metric icon={<GitBranch size={18} />} label="Mode" value={integrationLabel(state)} />
        <Metric icon={<Clock3 size={18} />} label="Queued Patches" value={items.queue.length} />
        <Metric icon={<Activity size={18} />} label="Active Sessions" value={items.active.length} />
        <Metric icon={<CheckCircle2 size={18} />} label="Pushed Commits" value={items.commits.length} />
      </section>
      <section className="integration-stack">
        <section className="panel">
          <PanelTitle icon={<ListChecks size={17} />} title="Recent Runs" />
          <IntegrationQueue
            items={runs}
            onSelect={toggleRun}
            selectedRunId={selectedRunId}
          />
        </section>
        <section className="panel">
          <PanelTitle icon={<GitBranch size={17} />} title="Pushed Commits" />
          <IntegrationCommits commits={items.commits} />
        </section>
      </section>
    </div>
  );
}

function IntegrationQueue({
  items,
  onSelect,
  selectedRunId,
}: {
  items: IntegrationRun[];
  onSelect: (runId: string) => void;
  selectedRunId: string;
}) {
  const pagination = usePagination(items);
  const { pageSize, setPage } = pagination;
  const selectedIndex = selectedRunId
    ? items.findIndex((item) => item.run_id === selectedRunId)
    : -1;
  useEffect(() => {
    if (selectedIndex >= 0) {
      setPage(Math.floor(selectedIndex / pageSize) + 1);
    }
  }, [pageSize, selectedIndex, setPage]);
  if (!items.length) return <div className="empty-state">No Integration runs have been recorded yet.</div>;
  return (
    <>
      <div className="integration-list">
        {pagination.pageItems.map((item) => {
          const title = item.source_title || item.title;
          const commitSummary = item.remote.commit ? `pushed ${item.remote.commit}` : "";
          const summary = item.summary && item.summary !== commitSummary ? item.summary : "";
          const expanded = Boolean(item.run_id && item.run_id === selectedRunId);
          return (
            <article
              className={`integration-card ${expanded ? "active expanded" : ""}`}
              key={`${item.run_id || item.task_id || item.source_task_id}-${item.updated_at}`}
            >
              <div className="integration-card-summary">
                <div className="integration-card-main">
                  <div className="integration-card-head">
                    <StatusTextPill status={item.status} />
                    <time className="mono muted" dateTime={item.updated_at}>{shortDate(item.updated_at)}</time>
                  </div>
                  <h3>{title}</h3>
                  <div className="integration-meta-row compact">
                    <span className="integration-meta-chip">
                      <b>Stage</b>
                      <span>{integrationStageText(item)}</span>
                    </span>
                    {item.source_task_id && (
                      <Link className="integration-meta-chip link" href={taskHref(item.source_task_id)}>
                        <b>Source</b>
                        <span>Task</span>
                      </Link>
                    )}
                    {item.remote.commit && item.remote.commit_url && (
                      <a className="integration-meta-chip link" href={item.remote.commit_url} rel="noreferrer" target="_blank">
                        <b>Commit</b>
                        <span className="mono">{shortSha(item.remote.commit)}</span>
                        <ExternalLink size={13} />
                      </a>
                    )}
                  </div>
                  {summary && <p>{summary}</p>}
                </div>
                <div className="integration-actions">
                  {item.run_id ? (
                    <button
                      aria-expanded={expanded}
                      className="secondary"
                      onClick={() => onSelect(item.run_id)}
                      type="button"
                    >
                      {expanded ? "Hide Details" : "View Details"}
                    </button>
                  ) : (
                    <span className="muted">Run pending</span>
                  )}
                </div>
              </div>
              {expanded && <IntegrationSession run={item} />}
            </article>
          );
        })}
      </div>
      <PaginationControls
        itemLabel="integration runs"
        onPageChange={pagination.setPage}
        page={pagination.page}
        pageCount={pagination.pageCount}
        pageSize={pagination.pageSize}
        total={items.length}
      />
    </>
  );
}

function IntegrationSession({ run }: { run?: IntegrationRun }) {
  if (!run) return <div className="empty-state">No Integration run is selected.</div>;
  return (
    <div className="integration-session">
      <IntegrationInlineDetail key={`${run.run_id}-${run.updated_at}`} run={run} />
    </div>
  );
}

function IntegrationTranscriptPanel({ run }: { run: IntegrationRun }) {
  const [transcript, setTranscript] = useState("");
  useEffect(() => {
    let cancelled = false;
    if (run.run_id && run.transcript_path) {
      getTaskFile(run.run_id, "transcript").then((text) => {
        if (!cancelled) setTranscript(text);
      });
    }
    return () => {
      cancelled = true;
    };
  }, [run.run_id, run.transcript_path, run.updated_at]);
  return (
    <>
      <h3 className="section-subtitle">Integration Transcript</h3>
      {transcript ? (
        <CodeBlock className="integration-transcript" compact text={transcript} title="Transcript" />
      ) : (
        <div className="empty-state compact">No integration transcript has been captured yet.</div>
      )}
    </>
  );
}

function IntegrationInlineDetail({ run }: { run: IntegrationRun }) {
  const [detail, setDetail] = useState<IntegrationDetail | null>(null);
  const [patch, setPatch] = useState("");
  const [transcript, setTranscript] = useState("");
  const [validationLog, setValidationLog] = useState<{ index: number; text: string } | null>(null);
  const [activeTab, setActiveTab] = useState<IntegrationTab>("patch");
  const [loadError, setLoadError] = useState("");
  useEffect(() => {
    let cancelled = false;
    if (!run.run_id) return;
    async function load() {
      try {
        const [next, nextTranscript] = await Promise.all([
          getIntegration(run.run_id),
          getTaskFile(run.run_id, "transcript"),
        ]);
        let nextPatch = await getTaskFile(run.run_id, "patch");
        if (!nextPatch && next.run.source_task_id) {
          nextPatch = await getTaskFile(next.run.source_task_id, "patch");
        }
        if (!cancelled) {
          setDetail(next);
          setPatch(nextPatch);
          setTranscript(nextTranscript);
        }
      } catch (error) {
        if (!cancelled) setLoadError(errorMessage(error, "Unable to load integration detail."));
      }
    }
    void load();
    return () => {
      cancelled = true;
    };
  }, [run.run_id, run.updated_at]);

  async function showValidation(index: number) {
    if (!run.run_id) return;
    try {
      setValidationLog({ index, text: await getValidationLog(run.run_id, index) });
    } catch (error) {
      setLoadError(errorMessage(error, "Unable to load validation log."));
    }
  }

  if (loadError) return <div className="inline-alert">{loadError}</div>;
  if (!detail) {
    return (
      <>
        <IntegrationTranscriptPanel run={run} />
        <IntegrationTimeline events={run.events} />
      </>
    );
  }

  const timelineEvents = [...detail.events, ...detail.source_events]
    .sort((left, right) => left.created_at.localeCompare(right.created_at));
  const tabs = integrationTabs(detail, patch);
  return (
    <div className="integration-inline-detail">
      <div className="integration-detail-layout">
        <main className="integration-detail-main">
          <div className="attempt-tabs integration-tabs" role="tablist" aria-label="Integration run views">
            {tabs.map((tab) => (
              <button
                aria-selected={activeTab === tab.key}
                className={activeTab === tab.key ? "active" : ""}
                key={tab.key}
                onClick={() => setActiveTab(tab.key)}
                role="tab"
                type="button"
              >
                <span>{tab.label}</span>
                {tab.meta !== undefined && <b>{tab.meta}</b>}
              </button>
            ))}
          </div>
          <div className="attempt-panel integration-tab-panel">
            {activeTab === "patch" && <IntegrationPatchPanel patch={patch} />}
            {activeTab === "validation" && (
              <IntegrationValidations
                log={validationLog?.text || ""}
                logIndex={validationLog?.index ?? null}
                onShow={showValidation}
                validations={detail.validations}
              />
            )}
            {activeTab === "commit" && (
              <IntegrationCommitPanel
                detail={detail}
                transcript={transcript}
              />
            )}
            {activeTab === "push" && (
              <IntegrationPushPanel
                detail={detail}
                transcript={transcript}
              />
            )}
          </div>
        </main>
        <aside className="integration-detail-aside">
          <IntegrationTimeline events={timelineEvents} />
        </aside>
      </div>
    </div>
  );
}

function IntegrationTimeline({ events }: { events: IntegrationRun["events"] }) {
  const timelineEvents = events.slice().reverse();
  return (
    <section className="panel task-timeline-panel integration-timeline-panel">
      <PanelTitle icon={<ListChecks size={17} />} title="Timeline" />
      <ol className="timeline compact">
        {timelineEvents.map((event) => <TimelineEvent event={event} key={`${event.task_id}-${event.created_at}-${event.kind}`} />)}
        {!timelineEvents.length && <li className="muted">No Integration events recorded yet.</li>}
      </ol>
    </section>
  );
}

function IntegrationPatchPanel({ patch }: { patch: string }) {
  return (
    <section className="integration-subsection">
      <h3 className="section-subtitle">Patch</h3>
      {patch ? <DiffView text={patch} /> : <div className="empty-state compact">No integration patch artifact is available.</div>}
    </section>
  );
}

function IntegrationCommitPanel({
  detail,
  transcript,
}: {
  detail: IntegrationDetail;
  transcript: string;
}) {
  const commitMessage = parseCommitMessageArtifact(detail.commit_message?.last_message || "");
  const commitEvents = integrationEventsMatching(detail, [
    "integration.commit_message_generated",
    "integration.commit_message_failed",
    "integration.commit_failed",
    "integration.local_only",
  ]);
  const commitLines = filterIntegrationTranscript(transcript, ["commit_message", "commit", "commit_failed", "local_only"]);
  return (
    <section className="integration-subsection integration-artifact-panel">
      <h3 className="section-subtitle">Commit</h3>
      {commitMessage ? (
        <article className="commit-message-card">
          <span>Commit message</span>
          <h4>{commitMessage.subject}</h4>
          {commitMessage.body && <CodeBlock compact language="markdown" text={commitMessage.body} title="Body" />}
        </article>
      ) : (
        <div className="empty-state compact">No structured commit message has been captured yet.</div>
      )}
      {detail.commit_message?.transcript && (
        <TranscriptView
          diagnostics={detail.commit_message.diagnostics}
          prompt=""
          taskId={`${detail.run.run_id}-commit-message`}
          text={detail.commit_message.transcript}
        />
      )}
      <IntegrationEventList events={commitEvents} emptyText="No commit events recorded yet." />
      {commitLines && <CodeBlock compact text={commitLines} title="Commit transcript" />}
    </section>
  );
}

function IntegrationPushPanel({
  detail,
  transcript,
}: {
  detail: IntegrationDetail;
  transcript: string;
}) {
  const pushEvents = integrationEventsMatching(detail, ["main.pushed", "integration.push_failed"]);
  const pushLines = filterIntegrationTranscript(transcript, ["push", "push_failed", "pushed", "finish"]);
  const pushLog = detail.push_log?.text || "";
  return (
    <section className="integration-subsection integration-artifact-panel">
      <h3 className="section-subtitle">Push</h3>
      {detail.remote.commit && detail.remote.commit_url && (
        <div className="push-summary">
          <span>Remote commit</span>
          <GithubCommitLink commit={detail.remote.commit} url={detail.remote.commit_url} />
        </div>
      )}
      <IntegrationEventList events={pushEvents} emptyText="No push events recorded yet." />
      {pushLog ? (
        <CodeBlock compact text={pushLog} title="Push log" />
      ) : pushLines ? (
        <CodeBlock compact text={pushLines} title="Push transcript" />
      ) : (
        <div className="empty-state compact">No push transcript has been captured yet.</div>
      )}
    </section>
  );
}

function IntegrationValidations({
  log,
  logIndex,
  onShow,
  validations,
}: {
  log: string;
  logIndex: number | null;
  onShow: (index: number) => void;
  validations: Array<ValidationResult & { index: number }>;
}) {
  if (!validations.length) return <div className="empty-state compact">No integration validation has run yet.</div>;
  return (
    <div className="attempt-validation-list integration-validations">
      {validations.map((validation) => (
        <button
          className={`validation-row ${logIndex === validation.index ? "active" : ""}`}
          key={`${validation.output_path}-${validation.index}`}
          onClick={() => onShow(validation.index)}
          type="button"
        >
          {validation.passed ? <CheckCircle2 size={16} /> : <XCircle size={16} />}
          <span className="mono">{validation.command.join(" ")}</span>
          <StatusPill status={validation.passed ? "succeeded" : "failed"} />
        </button>
      ))}
      {log && validations.some((validation) => validation.index === logIndex) && (
        <CodeBlock compact text={log} title="Validation log" />
      )}
    </div>
  );
}

function IntegrationEventList({
  emptyText,
  events,
}: {
  emptyText: string;
  events: EventRecord[];
}) {
  if (!events.length) return <div className="empty-state compact">{emptyText}</div>;
  return (
    <div className="integration-event-list">
      {events.map((event) => (
        <article key={`${event.task_id}-${event.created_at}-${event.kind}`}>
          <div>
            <b className="mono">{event.kind}</b>
            <time className="mono muted" dateTime={event.created_at}>{shortDate(event.created_at)}</time>
          </div>
          <p>{event.message}</p>
        </article>
      ))}
    </div>
  );
}

function DiffView({ text }: { text: string }) {
  return <CodeBlock compact diffDisplay="unified-with-split-modal" language="diff" text={text} title="Patch" />;
}

function IntegrationCommits({
  commits,
}: {
  commits: StewardState["integration"]["commits"];
}) {
  const pagination = usePagination(commits);
  if (!commits.length) return <div className="empty-state">No pushed commits have been recorded yet.</div>;
  return (
    <>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Source Task</th>
              <th>Commit</th>
              <th>Status</th>
              <th>Updated</th>
            </tr>
          </thead>
          <tbody>
            {pagination.pageItems.map((commit) => (
              <tr key={`${commit.task_id}-${commit.commit}`}>
                <td>
                  <Link className="link-button" href={taskHref(commit.task_id)}>
                    {commit.title}
                  </Link>
                  <div className="task-meta mono">{commit.task_id}</div>
                  {commit.summary && <div className="task-meta">{commit.summary}</div>}
                </td>
                <td><GithubCommitLink commit={commit.commit} url={commit.commit_url} /></td>
                <td><StatusTextPill status={commit.status} /></td>
                <td className="mono">{shortDate(commit.updated_at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <PaginationControls
        itemLabel="pushed commits"
        onPageChange={pagination.setPage}
        page={pagination.page}
        pageCount={pagination.pageCount}
        pageSize={pagination.pageSize}
        total={commits.length}
      />
    </>
  );
}

function TaskTable({ githubRepository, tasks, selectedId }: {
  githubRepository: string;
  tasks: TaskRecord[];
  selectedId: string;
}) {
  const pagination = usePagination(tasks);
  const { pageSize, setPage } = pagination;
  const selectedIndex = selectedId
    ? tasks.findIndex((task) => task.spec.id === selectedId)
    : -1;
  useEffect(() => {
    if (selectedIndex >= 0) {
      setPage(Math.floor(selectedIndex / pageSize) + 1);
    }
  }, [pageSize, selectedIndex, setPage]);
  if (!tasks.length) return <div className="empty-state">No tasks yet. Create one or run a planning tick.</div>;
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
            {pagination.pageItems.map((task) => {
              const remote = taskRemoteFromSummary(task, githubRepository);
              const display = taskDisplay(task);
              return (
                <tr className={selectedId === task.spec.id ? "selected-row" : ""} key={task.spec.id}>
                  <td>
                    <Link className="link-button" href={taskHref(task.spec.id)}>
                      {display.title}
                    </Link>
                  </td>
                  <td><StatusPill status={task.status} /></td>
                  <td><TaskSpecChip value={display.kind} /></td>
                  <td><TaskSpecChip tone={`priority-${task.spec.priority}`} value={task.spec.priority} /></td>
                  <td><TaskSpecChip tone={`risk-${task.spec.risk}`} value={task.spec.risk} /></td>
                  <td>
                    <time className="compact-time mono" dateTime={task.updated_at} title={shortDate(task.updated_at)}>
                      {compactDate(task.updated_at)}
                    </time>
                  </td>
                  <td>{remote ? <GithubCommitLink commit={remote.commit} url={remote.url} /> : <span className="muted">-</span>}</td>
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

function TaskGraph({
  tasks,
  selectedId,
}: {
  tasks: TaskRecord[];
  selectedId: string;
}) {
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
              {laneTasks.map((task) => {
                const display = taskDisplay(task);
                return (
                  <Link
                    className={`graph-node ${selectedId === task.spec.id ? "active" : ""}`}
                    href={taskHref(task.spec.id)}
                    key={task.spec.id}
                    title={display.title}
                  >
                    <div className="graph-node-top">
                      <StatusPill status={task.status} />
                      <time className="graph-node-time mono" dateTime={task.updated_at} title={shortDate(task.updated_at)}>
                        Updated {compactDate(task.updated_at)}
                      </time>
                    </div>
                    <div className="graph-node-title">
                      <b>{display.title}</b>
                    </div>
                    <div className="graph-node-context">
                      <span>{isIntegrationTask(task) ? "Source" : "Agent"}</span>
                      <b>{display.worker}</b>
                    </div>
                    <div className="graph-node-meta">
                      <TaskSpecChip label="Type" value={display.kind} />
                      <TaskSpecChip label="Priority" tone={`priority-${task.spec.priority}`} value={task.spec.priority} />
                      <TaskSpecChip label="Risk" tone={`risk-${task.spec.risk}`} value={task.spec.risk} />
                    </div>
                  </Link>
                );
              })}
              {!laneTasks.length && <div className="lane-empty">{lane.empty}</div>}
            </div>
          </div>
        );
      })}
    </div>
  );
}

function taskUpdatedAtMs(task: TaskRecord) {
  const value = Date.parse(task.updated_at);
  return Number.isFinite(value) ? value : 0;
}

function GithubCommitLink({ commit, url }: { commit: string; url: string }) {
  return (
    <a className="commit-link" href={url} rel="noreferrer" target="_blank">
      <ExternalLink size={14} />
      <span className="mono">{shortSha(commit)}</span>
    </a>
  );
}

function StatusPill({ status }: { status: TaskStatus }) {
  return <span className={`status status-${status}`}>{status}</span>;
}

function StatusTextPill({ status }: { status: string }) {
  return <span className={`status status-${status}`}>{status || "-"}</span>;
}

function TaskSpecChip({
  label,
  tone,
  value,
}: {
  label?: string;
  tone?: string;
  value: string;
}) {
  return (
    <span className={`task-spec-chip ${tone || ""}`}>
      {label && <b>{label}</b>}
      <span>{value}</span>
    </span>
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

function countTasks(tasks: TaskRecord[]) {
  const terminal = new Set<TaskStatus>(["succeeded", "pushed", "no_changes", "blocked", "failed", "cancelled"]);
  const userTasks = tasks.filter((task) => !isIntegrationTask(task));
  const integration = tasks.filter(isIntegrationTask).length;
  return {
    total: userTasks.length,
    active: userTasks.filter((task) => ["running", "reviewing", "integrating"].includes(task.status)).length,
    queued: userTasks.filter((task) => task.status === "queued").length,
    terminal: userTasks.filter((task) => terminal.has(task.status)).length,
    integration,
    signals: 0,
  };
}

function schedulerState(state: StewardState) {
  return state.scheduler ?? EMPTY_STATE.scheduler!;
}

function taskDisplay(task: TaskRecord) {
  if (isIntegrationTask(task)) {
    const source = typeof task.spec.metadata.source_task_id === "string" ? task.spec.metadata.source_task_id : "";
    return {
      title: task.spec.title.replace(/^Integrate\b/, "Integration"),
      kind: "integration",
      worker: source ? `Integration · ${source}` : "Integration",
    };
  }
  return {
    title: task.spec.title,
    kind: task.spec.kind,
    worker: task.spec.worker,
  };
}

function isIntegrationTask(task: TaskRecord) {
  return task.spec.kind === "integration" || task.spec.worker === "integration-manager";
}

function taskMatchesSignal(task: TaskRecord, item: SignalItem) {
  const metadata = task.spec.metadata;
  const evidence = Array.isArray(metadata.evidence) ? metadata.evidence : [];
  if (evidence.some((value) => value === item.id)) {
    return true;
  }
  const selected = Array.isArray(metadata.selected_signal_item_ids)
    ? metadata.selected_signal_item_ids
    : [];
  if (selected.some((value) => value === item.id)) {
    return true;
  }
  const sourceContext = metadata.source_context;
  if (sourceContext && typeof sourceContext === "object" && !Array.isArray(sourceContext)) {
    const sourceIds = (sourceContext as Record<string, unknown>).selected_signal_item_ids;
    if (Array.isArray(sourceIds) && sourceIds.some((value) => value === item.id)) {
      return true;
    }
  }
  const candidates = [
    metadata.signal_id,
    metadata.source_signal_id,
    metadata.planner_run_id,
  ];
  return candidates.some(
    (value) =>
      value === item.id
      || (item.planner_run_id !== null && value === item.planner_run_id),
  );
}

function primarySignalLink(item: SignalItem): { label: string; url: string } | null {
  const links = Array.isArray(item.links) ? item.links : [];
  const link = links.find((candidate) => candidate.url);
  return link ?? null;
}

function signalLocationLabel(item: SignalItem) {
  const location = item.location;
  if (!location) return "";
  const path = typeof location.path === "string" ? location.path : "";
  const line = typeof location.line === "number" || typeof location.line === "string" ? location.line : "";
  if (path && line !== "") return `${path}:${line}`;
  return path;
}

function integrationLabel(state: StewardState) {
  if (!state.config.integration_mode) return "-";
  if (state.config.integration_mode === "push-main" && state.config.local_only) {
    return "push-main · local only";
  }
  return state.config.integration_mode;
}

function viewTitle(view: ViewKey) {
  const titles: Record<ViewKey, string> = {
    control: "Control Loop",
    tasks: "Tasks",
    integration: "Integration",
    signals: "Signals",
    configuration: "Configuration",
  };
  return titles[view];
}

function taskHref(taskId: string) {
  return `/tasks/${encodeURIComponent(taskId)}`;
}

function codacySignal(summary: string, repository = ""): CodacySignal | null {
  const match = /(?:^|\b)Codacy\s+issuesCount=(\d+)/i.exec(summary);
  if (!match) return null;
  return {
    count: Number.parseInt(match[1], 10),
    url: repository ? `https://app.codacy.com/gh/${repository}/issues/current` : null,
  };
}

function repositoryFromPayload(payload: Record<string, unknown>) {
  const value = payload.github_repository;
  return typeof value === "string" ? value : "";
}

function integrationStageText(item: IntegrationRun) {
  const latest = item.events.at(-1)?.kind || "";
  if (item.status === "queued") return "Queued for serialized main update";
  if (latest === "main.pushed" || item.remote.commit) return "Pushed to main";
  if (latest === "integration.source" || latest === "integration.started") return "Applying patch on latest main";
  if (latest === "integration.conflict") return "Needs conflict resolution";
  if (latest === "integration.push_failed") return "Push failed";
  if (item.status === "running" || item.status === "integrating") return "Integration lane active";
  if (item.status === "succeeded") return "Committed locally";
  if (item.status === "failed" || item.status === "blocked") return "Needs attention";
  return item.summary || item.status || "-";
}

function integrationRuns(items: StewardState["integration"], tasks: TaskRecord[]) {
  const byId = new Map<string, IntegrationRun>();
  for (const run of [...integrationTaskRuns(items, tasks), ...(items.runs ?? []), ...items.active, ...items.queue]) {
    const key = run.run_id || run.task_id;
    if (key) byId.set(key, run);
  }
  return Array.from(byId.values()).sort((left, right) => right.updated_at.localeCompare(left.updated_at));
}

function integrationTaskRuns(items: StewardState["integration"], tasks: TaskRecord[]): IntegrationRun[] {
  const byTaskId = new Map(tasks.map((task) => [task.spec.id, task]));
  const commitsByTaskId = new Map(items.commits.map((commit) => [commit.task_id, commit]));
  return tasks
    .filter(isIntegrationTask)
    .map((task) => {
      const sourceTaskId = typeof task.spec.metadata.source_task_id === "string" ? task.spec.metadata.source_task_id : "";
      const source = sourceTaskId ? byTaskId.get(sourceTaskId) : undefined;
      const sourcePatchPath = typeof task.spec.metadata.source_patch_path === "string" ? task.spec.metadata.source_patch_path : null;
      const commit = commitsByTaskId.get(task.spec.id) ?? (sourceTaskId ? commitsByTaskId.get(sourceTaskId) : undefined);
      return {
        run_id: task.spec.id,
        task_id: task.spec.id,
        title: task.spec.title,
        status: task.status,
        summary: task.summary,
        source_task_id: sourceTaskId || null,
        source_title: source?.spec.title || "",
        source_status: source?.status || "",
        source_patch_path: source?.patch_path || sourcePatchPath,
        patch_path: task.patch_path || source?.patch_path || sourcePatchPath,
        transcript_path: task.transcript_path,
        worktree_path: task.worktree_path,
        updated_at: task.updated_at,
        remote: {
          commit: commit?.commit || null,
          commit_url: commit?.commit_url || null,
        },
        events: [],
      };
    })
    .sort((left, right) => right.updated_at.localeCompare(left.updated_at));
}

function integrationTabs(detail: IntegrationDetail, patch: string): Array<{ key: IntegrationTab; label: string; meta?: string | number }> {
  const commitReady = Boolean(detail.commit_message?.last_message || integrationEventsMatching(detail, ["integration.commit_message_generated"]).length);
  const pushEvents = integrationEventsMatching(detail, ["main.pushed", "integration.push_failed"]);
  return [
    { key: "patch", label: "Patch", meta: patch ? "saved" : undefined },
    { key: "validation", label: "Validation", meta: detail.validations.length },
    { key: "commit", label: "Commit", meta: commitReady ? "ready" : undefined },
    { key: "push", label: "Push", meta: detail.remote.commit ? "pushed" : pushEvents.length || undefined },
  ];
}

function integrationEventsMatching(detail: IntegrationDetail, kinds: string[]) {
  const wanted = new Set(kinds);
  return [...detail.events, ...detail.source_events]
    .filter((event) => wanted.has(event.kind))
    .sort((left, right) => left.created_at.localeCompare(right.created_at));
}

function filterIntegrationTranscript(transcript: string, stages: string[]) {
  if (!transcript.trim()) return "";
  const wanted = new Set(stages);
  return transcript
    .split("\n")
    .filter((line) => {
      const match = /^\[[^\]]+\]\s+([^:]+):/.exec(line);
      return match ? wanted.has(match[1]) : false;
    })
      .join("\n");
}

function parseCommitMessageArtifact(text: string): { subject: string; body: string } | null {
  if (!text.trim()) return null;
  try {
    const parsed = JSON.parse(text) as Record<string, unknown>;
    const subject = parsed.subject;
    const body = parsed.body;
    if (typeof subject === "string" && typeof body === "string") {
      return { subject, body };
    }
  } catch {
    return null;
  }
  return null;
}

function providerStatusText(provider: SchedulerProviderState) {
  const interval = provider.last_status === "error" ? provider.error_retry_minutes : provider.poll_interval_minutes;
  if (provider.due) return `Due now · ${provider.max_items} item limit`;
  if (provider.idle_due) return `Idle fetch due now · ${provider.max_items} item limit`;
  if (provider.idle_next_due_at && isBefore(provider.idle_next_due_at, provider.next_due_at)) {
    return `Idle fetch ${compactFuture(provider.idle_next_due_at)} · idle every ${formatMinutes(provider.idle_poll_interval_minutes)}`;
  }
  return `Next ${compactFuture(provider.next_due_at)} · every ${formatMinutes(interval)}`;
}

function isBefore(left: string, right: string) {
  return new Date(left).getTime() < new Date(right).getTime();
}

function wakeupDetailEntries(wakeup: SchedulerWakeup) {
  const entries: Array<{ label: string; value: string; mono?: boolean }> = [];
  const consumedKeys = new Set<string>();
  const add = (label: string, value: unknown, mono = false, keys: string[] = []) => {
    if (value === null || value === undefined || value === "") return;
    const text = Array.isArray(value)
      ? value.filter((item) => item !== null && item !== undefined && item !== "").join(", ")
      : typeof value === "object"
        ? JSON.stringify(value)
        : String(value);
    if (!text) return;
    keys.forEach((key) => consumedKeys.add(key));
    entries.push({ label, value: text, mono });
  };

  add("wakeup", wakeup.id, true);
  add("state", wakeup.status);
  add("providers", wakeup.data.providers, false, ["providers"]);
  add("provider", wakeup.data.provider, false, ["provider"]);
  add("task", wakeup.data.task_id, true, ["task_id"]);
  add("signal", wakeup.data.signal_item_id, true, ["signal_item_id"]);
  add("status", wakeup.data.status, false, ["status"]);
  add("phase", wakeup.data.phase, false, ["phase"]);
  add("dispatch", wakeup.data.dispatch, false, ["dispatch"]);
  add("plan", wakeup.data.plan, false, ["plan"]);
  add("max dispatch", wakeup.data.max_dispatch, false, ["max_dispatch"]);
  for (const [key, value] of Object.entries(wakeup.data)) {
    if (!consumedKeys.has(key)) add(key.replaceAll("_", " "), value, false, [key]);
  }
  return entries;
}

function taskRemoteFromSummary(task: TaskRecord, githubRepository: string) {
  if (task.status !== "pushed" || !githubRepository) return null;
  const match = /^pushed\s+([0-9a-fA-F]{7,40})$/.exec(task.summary.trim());
  if (!match) return null;
  return {
    commit: match[1],
    url: `https://github.com/${githubRepository}/commit/${match[1]}`,
  };
}

function shortSha(value: string) {
  return value.slice(0, 12);
}

function projectId(stateDir: string) {
  if (!stateDir) return "-";
  return stateDir.split("/").filter(Boolean).at(-1) || stateDir;
}

function errorMessage(error: unknown, fallback: string) {
  if (error instanceof Error && error.message) return error.message;
  if (typeof error === "string" && error.trim()) return error;
  return fallback;
}

function shortDate(value: string) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString();
}

function compactDate(value: string) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const minute = 60 * 1000;
  const hour = 60 * minute;
  const day = 24 * hour;
  if (diffMs >= 0 && diffMs < minute) return "now";
  if (diffMs >= 0 && diffMs < hour) return `${Math.floor(diffMs / minute)}m`;
  if (diffMs >= 0 && diffMs < day) return `${Math.floor(diffMs / hour)}h`;
  if (diffMs >= 0 && diffMs < 7 * day) return `${Math.floor(diffMs / day)}d`;
  return date.toLocaleDateString(undefined, { month: "numeric", day: "numeric" });
}

function compactFuture(value: string) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  const diffMs = date.getTime() - Date.now();
  const minute = 60 * 1000;
  const hour = 60 * minute;
  if (diffMs <= 0) return "now";
  if (diffMs < hour) return `in ${Math.ceil(diffMs / minute)}m`;
  if (diffMs < 24 * hour) return `in ${Math.ceil(diffMs / hour)}h`;
  return date.toLocaleDateString(undefined, { month: "numeric", day: "numeric" });
}

function formatMinutes(value: number) {
  if (value < 60) return `${value}m`;
  const hours = value / 60;
  return Number.isInteger(hours) ? `${hours}h` : `${hours.toFixed(1)}h`;
}

function formatOptionalMinutes(value: number | null | undefined) {
  return typeof value === "number" ? formatMinutes(value) : "-";
}

function formatBytes(value: number) {
  if (!Number.isFinite(value) || value <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  let size = value;
  let unit = 0;
  while (size >= 1024 && unit < units.length - 1) {
    size /= 1024;
    unit += 1;
  }
  return `${size >= 10 || unit === 0 ? size.toFixed(0) : size.toFixed(1)} ${units[unit]}`;
}

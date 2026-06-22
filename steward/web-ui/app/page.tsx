"use client";

import Link from "next/link";
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  ChevronDown,
  Circle,
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
  X,
} from "lucide-react";
import { type FormEvent, type ReactNode, useEffect, useMemo, useState } from "react";
import {
  createTask,
  getTaskFile,
  getPlannerRun,
  getPlannerRuns,
  getState,
} from "./api";
import { TimelineEvent } from "./timeline";
import { TranscriptView } from "./transcript";
import type {
  IntegrationRun,
  PlannerRunArtifact,
  PlannerRunSummary,
  SignalItem,
  StewardState,
  TaskRecord,
  TaskStatus,
} from "./types";

type ViewKey = "control" | "tasks" | "integration" | "settings";

type CodacySignal = {
  count: number;
  url: string | null;
};

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
  config: {
    repo_root: "",
    state_dir: "",
    worktrees_dir: "",
    integration_mode: "",
    local_only: false,
    main_branch: "",
    github_repository: "",
    enabled_signals: [],
  },
};

export default function Dashboard() {
  const [state, setState] = useState<StewardState>(EMPTY_STATE);
  const [selectedId, setSelectedId] = useState<string>("");
  const [plannerRuns, setPlannerRuns] = useState<PlannerRunSummary[]>([]);
  const [busy, setBusy] = useState(false);
  const [streamState, setStreamState] = useState("connecting");
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
    getPlannerRuns().then(setPlannerRuns);
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

  const counts = {
    ...countTasks(state.tasks),
    signals: state.signal_inbox?.items.length ?? 0,
  };

  return (
    <main className="app-frame">
      <aside className="sidebar">
        <div className="sidebar-brand">
          <div className="brand-mark">CS</div>
          <div className="brand-copy">
            <h1>CoQUIC Steward</h1>
            <ProjectSelector counts={counts} state={state} />
          </div>
        </div>
        <SectionNav active={view} counts={counts} onSelect={setView} />
      </aside>

      <section className="app-shell">
        {view === "control" && (
          <header className="topbar">
            <div className="top-title">
              <h1>{viewTitle(view)}</h1>
              <span className={`stream-pill ${streamState}`}>{streamState}</span>
            </div>
            <div className="top-actions">
              <button className="icon-button" onClick={refresh} type="button" title="Refresh state">
                <RefreshCw size={16} />
              </button>
              <button className="icon-button" onClick={() => setCreateOpen(true)} type="button" title="Create task" aria-label="Create task">
                <Plus size={16} />
              </button>
            </div>
          </header>
        )}

        <DashboardView
          counts={counts}
          loadError={loadError}
          onRefresh={refresh}
          plannerRuns={plannerRuns}
          selectedTask={selectedTask}
          state={state}
          view={view}
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

function ProjectSelector({ counts, state }: { counts: ReturnType<typeof countTasks>; state: StewardState }) {
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
    { icon: <Inbox size={17} />, key: "settings", label: "Signals", meta: counts.signals },
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
  counts,
  loadError,
  onRefresh,
  plannerRuns,
  selectedTask,
  state,
  view,
}: {
  counts: ReturnType<typeof countTasks>;
  loadError: string;
  onRefresh: () => Promise<void>;
  plannerRuns: PlannerRunSummary[];
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
          items={state.integration ?? { queue: [], active: [], commits: [] }}
          state={state}
        />
      </>
    );
  }
  if (view === "settings") {
    return (
      <>
        {alert}
        <SignalsPanel state={state} tasks={userTasks} />
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
          <PlannerTranscriptPanel runs={plannerRuns} />
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

function PlannerTranscriptPanel({ runs }: { runs: PlannerRunSummary[] }) {
  return (
    <section className="panel">
      <PanelTitle icon={<FileText size={17} />} title="Planner Iterations" />
      {runs.length ? (
        <div className="planner-run-list">
          {runs.map((run, index) => (
            <PlannerRunCard
              index={index}
              key={run.run_id}
              run={run}
              turn={runs.length - index}
            />
          ))}
        </div>
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

function SignalsPanel({ state, tasks }: { state: StewardState; tasks: TaskRecord[] }) {
  const items = state.signal_inbox?.items ?? [];
  const fetchRuns = state.signal_inbox?.fetch_runs ?? [];
  const repository = state.config.github_repository || state.signals.repository;
  const [detailId, setDetailId] = useState("");
  const selected = items.find((item) => item.id === detailId) ?? null;
  const pending = items.filter((item) => item.status === "pending").length;
  const planned = items.filter((item) => item.status === "planned").length;
  return (
    <div className="signals-page">
      <section className="metrics">
        <Metric icon={<Inbox size={18} />} label="Signal Items" value={items.length} />
        <Metric icon={<Clock3 size={18} />} label="Pending" value={pending} />
        <Metric icon={<CheckCircle2 size={18} />} label="Planned" value={planned} />
        <Metric icon={<AlertTriangle size={18} />} label="Fetch Errors" value={fetchRuns.filter((run) => run.status === "error").length} />
      </section>
      <section className="signals-stack">
        <FoldablePanel defaultOpen icon={<Inbox size={17} />} meta={items.length} title="Signal Inbox">
          <SignalInboxList
            items={items}
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

function SignalInboxList({
  items,
  onSelect,
  repository,
  selectedId,
}: {
  items: SignalItem[];
  onSelect: (id: string) => void;
  repository: string;
  selectedId: string;
}) {
  if (!items.length) return <div className="empty-state">No signal items have been recorded yet.</div>;
  return (
    <div className="signal-list">
      {items.map((item) => {
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
                  <TaskSpecChip value={display.kind} />
                </Link>
              );
            })}
          </div>
        ) : (
          <div className="empty-state compact">No user-facing task is linked to this signal yet.</div>
        )}
      </div>
      <h3 className="section-subtitle">Payload</h3>
      <pre className="code-pane compact">{JSON.stringify(item.payload, null, 2)}</pre>
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
          <PanelTitle icon={<ListChecks size={17} />} title="Submission Queue" />
          <IntegrationQueue items={items.queue} />
        </section>
        <section className="panel">
          <PanelTitle icon={<Activity size={17} />} title="Integration Session" />
          <IntegrationSession items={items.active} />
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
}: {
  items: IntegrationRun[];
}) {
  if (!items.length) return <div className="empty-state">No patches are waiting for Integration.</div>;
  return (
    <div className="integration-list">
      {items.map((item) => (
        <article className="integration-card" key={`${item.run_id || item.task_id || item.source_task_id}-${item.updated_at}`}>
          <div className="integration-card-main">
            <div className="integration-card-head">
              <StatusTextPill status={item.status} />
              <time className="mono muted" dateTime={item.updated_at}>{shortDate(item.updated_at)}</time>
            </div>
            <h3>{item.source_title || item.title}</h3>
            <div className="integration-meta-row">
              <span>{integrationStageText(item)}</span>
              {item.source_task_id && <Link className="commit-link" href={taskHref(item.source_task_id)}>Source task</Link>}
              {item.remote.commit && item.remote.commit_url && <GithubCommitLink commit={item.remote.commit} url={item.remote.commit_url} />}
            </div>
            {item.summary && <p>{item.summary}</p>}
          </div>
          <div className="integration-actions">
            {item.run_id ? (
              <Link className="button-link secondary" href={integrationHref(item.run_id)}>
                Open Run
              </Link>
            ) : (
              <span className="muted">Run pending</span>
            )}
          </div>
        </article>
      ))}
    </div>
  );
}

function IntegrationSession({
  items,
}: {
  items: IntegrationRun[];
}) {
  const active = items[0];
  if (!active) return <div className="empty-state">No Integration session is currently running.</div>;
  const timelineEvents = active.events.slice().reverse();
  return (
    <div className="integration-session">
      <div className="session-head">
        <div>
          <StatusTextPill status={active.status} />
          <h3>{active.title}</h3>
          <p>{active.summary || "Integration is preparing, validating, or pushing the reviewed patch."}</p>
        </div>
        {active.run_id && <Link className="button-link secondary" href={integrationHref(active.run_id)}>Open Run</Link>}
      </div>
      <div className="session-summary-grid">
        <div>
          <span>Current Stage</span>
          <b>{integrationStageText(active)}</b>
        </div>
        <div>
          <span>Source</span>
          {active.source_task_id ? <Link className="link-button" href={taskHref(active.source_task_id)}>Source task</Link> : <b>-</b>}
        </div>
        <div>
          <span>Remote</span>
          {active.remote.commit && active.remote.commit_url ? <GithubCommitLink commit={active.remote.commit} url={active.remote.commit_url} /> : <b>-</b>}
        </div>
      </div>
      <IntegrationTranscriptPanel key={`${active.run_id}-${active.transcript_path || ""}-${active.updated_at}`} run={active} />
      <h3 className="section-subtitle">Execution Timeline</h3>
      <ol className="timeline compact">
        {timelineEvents.map((event) => <TimelineEvent event={event} key={`${event.created_at}-${event.kind}`} />)}
        {!active.events.length && <li className="muted">No Integration events recorded yet.</li>}
      </ol>
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
        <pre className="integration-transcript code-pane compact">{transcript}</pre>
      ) : (
        <div className="empty-state compact">No integration transcript has been captured yet.</div>
      )}
    </>
  );
}

function IntegrationCommits({
  commits,
}: {
  commits: StewardState["integration"]["commits"];
}) {
  if (!commits.length) return <div className="empty-state">No pushed commits have been recorded yet.</div>;
  return (
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
          {commits.map((commit) => (
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
  );
}

function TaskTable({ githubRepository, tasks, selectedId }: {
  githubRepository: string;
  tasks: TaskRecord[];
  selectedId: string;
}) {
  if (!tasks.length) return <div className="empty-state">No tasks yet. Create one or run a planning tick.</div>;
  return (
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
          {tasks.map((task) => {
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
  );
}

function TaskGraph({
  tasks,
  selectedId,
}: {
  tasks: TaskRecord[];
  selectedId: string;
}) {
  const lanes: TaskStatus[] = [
    "queued",
    "running",
    "reviewing",
    "integrating",
    "succeeded",
    "pushed",
    "no_changes",
    "blocked",
    "failed",
    "cancelled",
  ];
  return (
    <div className="graph">
      {lanes.map((lane) => {
        const laneTasks = tasks.filter((task) => task.status === lane);
        return (
          <div className="graph-lane" key={lane}>
            <div className="lane-title">{lane}</div>
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
                    <Circle size={10} />
                    <span>{display.title}</span>
                  </Link>
                );
              })}
            </div>
          </div>
        );
      })}
    </div>
  );
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
  tone,
  value,
}: {
  tone?: string;
  value: string;
}) {
  return (
    <span className={`task-spec-chip ${tone || ""}`}>
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
    settings: "Signals",
  };
  return titles[view];
}

function taskHref(taskId: string) {
  return `/tasks/${encodeURIComponent(taskId)}`;
}

function integrationHref(integrationId: string) {
  return integrationId ? `/integrations/${encodeURIComponent(integrationId)}` : "#";
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

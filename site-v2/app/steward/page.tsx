import type { Metadata } from "next";
import { ArrowRight, ExternalLink } from "lucide-react";
import Link from "next/link";
import { SiteHeader } from "@/components/site-header";
import { getGitHubStars } from "@/lib/github";
import { readStewardLiveSnapshot } from "@/lib/steward-live/reader";
import type { StewardLiveSnapshot } from "@/lib/steward-live/schema";
import {
  getCloudRepository,
  type CloudTaskPage,
} from "@/lib/steward-archive/cloud-repository";
import type {
  CloudStatus,
  CloudTaskSummary,
  CloudUsageGlobalGroup,
  CloudUsageReadResult,
  CloudUsageSummary,
  CloudUsageUnavailable,
} from "@/lib/steward-archive/cloud-schema";
import {
  TaskUsageSummary,
  UsageEvidence,
  isUsageUnavailable,
} from "./usage-summary";

export const metadata: Metadata = {
  title: "Steward",
  description: "Inspect the public evidence behind CoQUIC repository automation.",
};
export const dynamic = "force-dynamic";
export const revalidate = 0;

const views = ["signals", "planning", "tasks"] as const;
type View = (typeof views)[number];

function titleCase(value: string) {
  return value
    .replace(/([A-Z])/g, " $1")
    .replace(/[._-]/g, " ")
    .replace(/^./, (letter) => letter.toUpperCase());
}

function formatDateTime(value: string | null) {
  if (!value) return "Unavailable";
  return new Intl.DateTimeFormat("en-US", {
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
    timeZone: "UTC",
    timeZoneName: "short",
  }).format(new Date(value));
}

function formatAge(value: string) {
  const seconds = Math.max(0, Math.floor((Date.now() - Date.parse(value)) / 1000));
  if (seconds < 5) return "just now";
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 48) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

function liveValue(snapshot: StewardLiveSnapshot | null, value: string | number) {
  if (!snapshot) return "Unavailable";
  return snapshot.availability === "stale" ? `${value} (stale)` : String(value);
}

function statusTone(value: string) {
  return value === "active" || value === "available"
    ? "text-accent"
    : value === "completed"
      ? "text-positive"
      : value === "failed" || value === "cancelled"
        ? "text-negative"
        : "text-muted";
}

function Status({ value }: { value: string }) {
  return <span className={`font-medium ${statusTone(value)}`}>{titleCase(value)}</span>;
}

function ControlLoop({
  activeView,
  liveSnapshot,
  historyPage,
}: {
  activeView: View;
  liveSnapshot: StewardLiveSnapshot | null;
  historyPage: CloudTaskPage | null;
}) {
  const steps: readonly {
    id: View | null;
    label: string;
    value: string;
    detail: string;
    href: string;
    station: string;
    schematic: string;
    workflow: readonly [string, string, string];
  }[] = [
    {
      id: "signals",
      label: "Signals",
      value: liveValue(liveSnapshot, liveSnapshot?.signals.pending ?? ""),
      detail: "pending",
      href: "/steward?view=signals",
      station: "Observation intake",
      schematic: "M0 24H56L88 48 M0 48H88 M0 72H56L88 48 M88 24H144V72H88Z M100 36H132 M100 48H132 M100 60H120 M144 48H240",
      workflow: ["Incoming repository observations.", "Collect signals for planning to consider.", "Pending signals awaiting triage."],
    },
    {
      id: "planning",
      label: "Planning",
      value: liveValue(liveSnapshot, liveSnapshot ? titleCase(liveSnapshot.planning.state) : ""),
      detail: "planner state",
      href: "/steward?view=planning",
      station: "Triage and plan selection",
      schematic: "M0 48H64 M64 48L104 12L144 48L104 84Z M88 48L100 60L120 36 M144 48H168 M168 24H216V72H168Z M180 36H204 M180 48H204 M180 60H196 M216 48H240",
      workflow: ["Pending signals.", "Triage observations and select a plan.", "Planned work for task execution; no live run details are published."],
    },
    {
      id: "tasks",
      label: "Tasks",
      value: liveValue(liveSnapshot, liveSnapshot ? `${liveSnapshot.tasks.active} / ${liveSnapshot.tasks.queued}` : ""),
      detail: "active / queued",
      href: "/steward?view=tasks",
      station: "Parallel task workbench",
      schematic: "M0 48H40 M40 20V76 M40 20H72 M40 48H72 M40 76H72 M72 8H168V32H72Z M72 36H168V60H72Z M72 64H168V88H72Z M84 20H124 M84 48H124 M84 76H124 M140 18L146 24L156 14 M140 46L146 52L156 42 M140 74L146 80L156 70 M168 20H200 M168 48H240 M168 76H200 M200 20V76",
      workflow: ["Planned tasks.", "Execute work in parallel and validate results.", "Task output and validation evidence for review."],
    },
    {
      id: null,
      label: "Integration",
      value: liveValue(liveSnapshot, liveSnapshot ? `${liveSnapshot.integration.active} / ${liveSnapshot.integration.queued}` : ""),
      detail: "active / queued",
      href: "/steward?view=tasks",
      station: "Reviewed output convergence",
      schematic: "M0 20H48L88 48 M0 48H88 M0 76H48L88 48 M88 24H144V72H88Z M100 48L112 60L132 36 M144 48H176 M176 16H216L232 32V80H176Z M216 16V32H232 M188 48H220 M188 60H212 M232 48H240",
      workflow: ["Task output and review evidence.", "Bring reviewed work together for integration.", "Integrated repository output. Published task evidence remains in the archive."],
    },
  ];

  return (
    <section
      aria-label="Steward task channels"
      className="mt-9 border-y border-line bg-surface text-ink"
    >
      <figure aria-labelledby="production-line-title">
        <figcaption className="px-4 pt-5">
          <h2 id="production-line-title" className="text-lg font-semibold">From observation to integrated output</h2>
          <p className="mt-2 text-sm text-muted">Explore the conceptual workflow; the values below each station are the aggregate snapshot, not individual job tracking.</p>
        </figcaption>
        <ol aria-label="Production line in workflow order" className="grid gap-8 p-4 sm:grid-cols-2 lg:grid-cols-4">
          {steps.map((step, index) => {
            const selected = step.id === activeView;
            return (
              <li key={step.label} className="relative min-w-0">
                <Link
                  href={step.href}
                  aria-current={selected ? "page" : undefined}
                  className={`relative block min-w-0 px-4 py-4 text-ink no-underline focus-visible:bg-accent-soft ${selected ? "bg-accent-soft" : "hover:bg-canvas"}`}
                >
                  <span className={`flex items-baseline justify-between gap-2 text-sm font-medium ${selected ? "text-accent" : "text-muted"}`}>
                    <span>{step.label}</span><span aria-hidden="true" className="text-xs">0{index + 1}</span>
                  </span>
                  <svg aria-hidden="true" viewBox="0 0 240 96" className="my-3 h-24 w-full text-ink" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinejoin="round">
                    <path d={step.schematic} />
                    <path d="M234 42L240 48L234 54" />
                  </svg>
                  <span className="block text-sm font-medium">{step.station}</span>
                  <span className="mt-4 block border-t border-line pt-3">
                    <span className="block text-xs text-muted">Snapshot · {step.detail}</span>
                    <span className="mt-1 block text-2xl font-medium data-text">{step.value}</span>
                  </span>
                  {selected ? <span className="absolute inset-x-0 bottom-0 h-0.5 border-b-2 border-accent bg-accent" /> : null}
                </Link>
                <details className="mt-2 border-b border-line">
                  <summary className="cursor-pointer px-4 py-3 text-sm font-medium text-muted">How {step.label} works</summary>
                  <div className="px-4 pb-4">
                    <p className="text-xs text-muted">Conceptual workflow, not live telemetry.</p>
                    <dl className="mt-3 space-y-3 text-sm">
                      {step.workflow.map((description, item) => (
                        <div key={description}>
                          <dt className="font-medium">{["Input", "Work", "Output"][item]}</dt>
                          <dd className="mt-1 text-muted">{description}</dd>
                        </div>
                      ))}
                    </dl>
                  </div>
                </details>
                {index < 3 ? (
                  <>
                    <span className="sr-only">{step.label} → {steps[index + 1]!.label}</span>
                    <svg aria-hidden="true" viewBox="0 0 32 32" fill="none" stroke="currentColor" strokeWidth="1.8"
                      className={`absolute -bottom-8 left-1/2 h-8 w-8 -translate-x-1/2 rotate-90 text-muted sm:-right-8 sm:bottom-auto sm:left-auto sm:top-20 sm:translate-x-0 sm:rotate-0 ${index === 1 ? "sm:hidden lg:block" : ""}`}>
                      <path d="M0 16H30 M24 10L30 16L24 22" />
                    </svg>
                    {index === 1 ? (
                      <svg aria-hidden="true" viewBox="0 0 100 32" preserveAspectRatio="none" fill="none" stroke="currentColor" strokeWidth="1.8"
                        className="absolute -bottom-8 right-1/2 hidden h-8 w-[calc(100%+2rem)] text-muted sm:block lg:hidden">
                        <path d="M100 0V16H1V30 M0 24L1 30L2 24" vectorEffect="non-scaling-stroke" />
                      </svg>
                    ) : null}
                  </>
                ) : null}
              </li>
            );
          })}
        </ol>
        <p className="border-t border-line px-4 py-3 text-xs text-muted">
          Arrows show workflow direction, not activity. Freshness is reported above. Archive history: <span className="data-text">{historyPage?.total ?? "Unavailable"}</span> · independent of live counts.
        </p>
      </figure>
    </section>
  );
}

function SectionOpening({
  label,
  title,
  description,
}: {
  label: string;
  title: string;
  description: string;
}) {
  return (
    <div className="grid gap-4 border-b border-line pb-7 lg:grid-cols-[13rem_minmax(0,1fr)] lg:gap-10">
      <p className="text-sm font-medium text-muted">{label}</p>
      <div>
        <h2 className="text-2xl font-semibold leading-tight text-ink">{title}</h2>
        <p className="mt-3 max-w-3xl text-base leading-7 text-muted">{description}</p>
      </div>
    </div>
  );
}

function UnavailableView({ title, description }: { title: string; description: string }) {
  return (
    <div className="py-10 sm:py-12">
      <SectionOpening label="Live control loop" title={title} description={description} />
      <p className="mt-8 border-y border-line py-8 text-sm text-muted">
        No local fallback or fixture records are displayed.
      </p>
    </div>
  );
}

function LiveDomainView({
  domain,
  snapshot,
}: {
  domain: "signals" | "planning";
  snapshot: StewardLiveSnapshot | null;
}) {
  const label = titleCase(domain);
  if (!snapshot) {
    return (
      <UnavailableView
        title={`${label} live state unavailable`}
        description="The public live snapshot could not be read. Archive task publications remain independent."
      />
    );
  }
  const stale = snapshot.availability === "stale";
  const value = domain === "signals" ? `${snapshot.signals.pending} pending` : titleCase(snapshot.planning.state);
  return (
    <div className="py-10 sm:py-12">
      <SectionOpening
        label="Live control loop"
        title={`${label} ${stale ? "snapshot stale" : "live state"}`}
        description={domain === "signals"
          ? "Pending signals come directly from the public Steward live snapshot."
          : "The planner state comes directly from the public Steward live snapshot."}
      />
      <dl className="mt-8 grid grid-cols-2 border-y border-line sm:grid-cols-4">
        {[
          [domain === "signals" ? "Pending" : "State", value],
          ["Availability", titleCase(snapshot.availability)],
          ["Daemon", titleCase(snapshot.daemon.mode)],
          ["Observed", formatAge(snapshot.observedAt)],
        ].map(([term, detail], index) => (
          <div key={term} className={`px-4 py-4 ${index < 3 ? "border-r border-line" : ""}`}>
            <dt className="text-xs text-muted">{term}</dt>
            <dd className="mt-1 text-lg font-medium text-ink data-text">{detail}</dd>
          </div>
        ))}
      </dl>
    </div>
  );
}

function TaskCompleteness({ task }: { task: CloudTaskSummary }) {
  const complete = task.completeness === "complete";
  return (
    <div className="flex items-center gap-2 text-xs text-muted">
      <span className={`size-2 shrink-0 ${complete ? "bg-positive" : "border border-line-strong"}`} />
      <span>{complete ? "Publication complete" : "Publication incomplete"}</span>
    </div>
  );
}

function TaskRowView({
  task,
  selected,
  usage,
}: {
  task: CloudTaskSummary;
  selected: boolean;
  usage: CloudUsageReadResult<CloudUsageSummary> | null;
}) {
  return (
    <li className={`border-b border-line py-4 ${selected ? "border-l-2 border-l-accent pl-4" : ""}`}>
      <div className="flex items-baseline justify-between gap-3 text-xs">
        <Status value={task.lifecycleState} />
        <span className="text-muted">{titleCase(task.completeness)}</span>
      </div>
      <Link
        href={`/steward/tasks/${encodeURIComponent(task.taskId)}`}
        className="mt-2 block break-words text-sm font-semibold leading-5 text-ink no-underline hover:text-accent"
      >
        {task.title}
      </Link>
      <p className="mt-1 break-words text-xs leading-5 text-muted data-text">{task.taskId}</p>
      <div className="mt-3">
        <TaskCompleteness task={task} />
      </div>
      <TaskUsageSummary usage={usage} />
    </li>
  );
}

function tasksHref(cursor: string | null, activeCursor: string | null) {
  const params = new URLSearchParams({ view: "tasks" });
  if (cursor) params.set("cursor", cursor);
  if (activeCursor) params.set("activeCursor", activeCursor);
  return `/steward?${params.toString()}`;
}

function TasksView({
  liveSnapshot,
  status,
  activePage,
  historyPage,
  cursor,
  activeCursor,
  globalUsage,
  taskUsage,
}: {
  liveSnapshot: StewardLiveSnapshot | null;
  status: CloudStatus | null;
  activePage: CloudTaskPage | null;
  historyPage: CloudTaskPage | null;
  cursor: string | null;
  activeCursor: string | null;
  globalUsage: CloudUsageGlobalGroup[] | CloudUsageUnavailable;
  taskUsage: ReadonlyMap<string, CloudUsageReadResult<CloudUsageSummary> | null>;
}) {
  const usageEvidence = <UsageEvidence usage={globalUsage} />;
  const summary = (
    <>
      <SectionOpening
        label="Live queues and cloud archive"
        title="Current task load and visible history"
        description="Live active and queued counts come from the public snapshot. Task history and detail remain independent D1/R2 archive evidence."
      />
      <dl className="mt-8 grid grid-cols-2 border-y border-line sm:grid-cols-4">
        {[
          ["Live active", liveValue(liveSnapshot, liveSnapshot?.tasks.active ?? "")],
          ["Live queued", liveValue(liveSnapshot, liveSnapshot?.tasks.queued ?? "")],
          ["Archive history", historyPage?.total ?? "Unavailable"],
          ["Latest archive", formatDateTime(status?.latestPublicationAt ?? null)],
        ].map(([label, value], index) => (
          <div key={String(label)} className={`px-4 py-4 ${index < 3 ? "border-r border-line" : ""}`}>
            <dt className="text-xs text-muted">{label}</dt>
            <dd className="mt-1 text-lg font-medium text-ink data-text">{value}</dd>
          </div>
        ))}
      </dl>
    </>
  );
  if (!status || !activePage || !historyPage) {
    return (
      <div className="py-10 sm:py-12">
        {summary}
        <p className="mt-8 border-y border-line py-8 text-sm text-muted">
          Cloud task archive unavailable. Live task counts remain independent when published above.
        </p>
        {usageEvidence}
      </div>
    );
  }

  const activeRows = activePage.tasks;
  const historyRows = historyPage.tasks;
  const selectedTask = activeRows[0] ?? historyRows[0] ?? null;
  return (
    <div className="py-10 sm:py-12">
      {summary}
      <section className="mt-8 border-y border-line xl:grid xl:grid-cols-[17rem_minmax(0,1fr)_19rem]" aria-labelledby="task-list-title">
        <div className="py-6 xl:border-r xl:border-line xl:pr-6">
          <div className="flex items-baseline justify-between gap-4">
            <h3 id="task-list-title" className="text-lg font-semibold text-ink">Active tasks</h3>
            <span className="text-xs text-muted data-text">{activePage.total}</span>
          </div>
          <ul className="mt-4 border-t border-line">
            {activeRows.map((task) => <TaskRowView key={task.taskId} task={task} selected={task.taskId === selectedTask?.taskId} usage={taskUsage.get(task.taskId) ?? null} />)}
          </ul>
          {activePage.total ? (
            <nav aria-label="Active task pages" className="mt-5 flex justify-between text-xs">
              {activePage.previousCursor ? <Link href={tasksHref(cursor, activePage.previousCursor)} className="text-accent">Previous active tasks</Link> : <span className="text-faint">First active page</span>}
              {activePage.nextCursor ? <Link href={tasksHref(cursor, activePage.nextCursor)} className="text-accent">Next active tasks</Link> : <span className="text-faint">End of active tasks</span>}
            </nav>
          ) : null}
          <div className="mt-8 flex items-baseline justify-between gap-4">
            <h3 className="text-sm font-semibold text-ink">Task history</h3>
            <span className="text-xs text-muted data-text">{historyPage.total}</span>
          </div>
          <ul className="mt-4 border-t border-line">
            {historyRows.map((task) => <TaskRowView key={task.taskId} task={task} selected={task.taskId === selectedTask?.taskId} usage={taskUsage.get(task.taskId) ?? null} />)}
          </ul>
          <nav aria-label="Task history pages" className="mt-5 flex justify-between text-xs">
            {historyPage.previousCursor ? <Link href={tasksHref(historyPage.previousCursor, activeCursor)} className="text-accent">Previous page</Link> : <span className="text-faint">First page</span>}
            {historyPage.nextCursor ? <Link href={tasksHref(historyPage.nextCursor, activeCursor)} className="text-accent">Next page</Link> : <span className="text-faint">End of history</span>}
          </nav>
        </div>
        <div className="min-w-0 py-6 xl:px-7">
          {selectedTask ? (
            <>
              <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                <div className="min-w-0">
                  <p className="text-xs font-medium text-accent">Selected task - {titleCase(selectedTask.lifecycleState)}</p>
                  <h3 className="mt-2 break-words text-xl font-semibold leading-tight text-ink">{selectedTask.title}</h3>
                  <p className="mt-2 text-sm leading-6 text-muted">{selectedTask.taskId}</p>
                </div>
                <Link href={`/steward/tasks/${encodeURIComponent(selectedTask.taskId)}`} className="inline-flex shrink-0 items-center gap-1.5 text-sm font-medium text-accent no-underline">
                  Full task detail <ArrowRight aria-hidden="true" size={14} />
                </Link>
              </div>
              <div className="mt-6 bg-contrast-field px-5 py-5 text-contrast-ink">
                <TaskCompleteness task={selectedTask} />
              </div>
              <dl className="mt-6 border-y border-line text-xs">
                <div className="flex justify-between border-b border-line py-3"><dt className="text-muted">Created</dt><dd className="text-right text-ink data-text">{formatDateTime(selectedTask.createdAt)}</dd></div>
                <div className="flex justify-between border-b border-line py-3"><dt className="text-muted">Completed</dt><dd className="text-right text-ink data-text">{formatDateTime(selectedTask.completedAt)}</dd></div>
                <div className="flex justify-between border-b border-line py-3"><dt className="text-muted">Events</dt><dd className="text-ink data-text">{selectedTask.eventCount}</dd></div>
                <div className="flex justify-between py-3"><dt className="text-muted">Artifacts</dt><dd className="text-ink data-text">{selectedTask.artifactCount}</dd></div>
              </dl>
            </>
          ) : (
            <p className="py-8 text-sm text-muted">No visible tasks are published yet.</p>
          )}
        </div>
        <aside className="py-6 xl:border-l xl:border-line xl:pl-6" aria-label="Cloud publication status">
          <div className="flex items-baseline justify-between gap-4">
            <h3 className="text-lg font-semibold text-ink">Publication status</h3>
            <Status value={status.state} />
          </div>
          <p className="mt-4 border-t border-line pt-4 text-sm leading-6 text-muted">
            {status.state === "empty" ? "No visible task publication has arrived." : "Visible task publications are available."}
          </p>
        </aside>
      </section>
      {usageEvidence}
    </div>
  );
}

export default async function StewardPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const params = await searchParams;
  const requested = typeof params.view === "string" ? params.view : "tasks";
  const activeView: View = views.includes(requested as View) ? requested as View : "tasks";
  const cursor = typeof params.cursor === "string" ? params.cursor : null;
  const activeCursor = typeof params.activeCursor === "string" ? params.activeCursor : null;
  const liveSnapshotPromise = readStewardLiveSnapshot().catch(() => null);
  let status: CloudStatus | null = null;
  let activePage: CloudTaskPage | null = null;
  let historyPage: CloudTaskPage | null = null;
  let globalUsage: CloudUsageGlobalGroup[] | CloudUsageUnavailable = {
    kind: "unavailable",
    reason: "unavailable",
  };
  const taskUsage = new Map<string, CloudUsageReadResult<CloudUsageSummary> | null>();

  let repository: ReturnType<typeof getCloudRepository> | null = null;
  try {
    repository = getCloudRepository();
    [status, activePage, historyPage] = await Promise.all([
      repository.getStatus(),
      repository.listActiveTasks({ cursor: activeCursor }),
      repository.listHistoryTasks({ cursor }),
    ]);
  } catch {
    status = null;
    activePage = null;
    historyPage = null;
  }

  if (repository) {
    const visibleTasks = [...new Map(
      [...(activePage?.tasks ?? []), ...(historyPage?.tasks ?? [])].map((task) => [task.taskId, task]),
    ).values()];
    const [globalResult, ...summaryResults] = await Promise.all([
      repository.getGlobalUsage().catch(() => ({ kind: "unavailable", reason: "unavailable" } as CloudUsageUnavailable)),
      ...visibleTasks.map((task) => repository!.getTaskUsageSummary(task.taskId).catch(() => ({ kind: "unavailable", reason: "unavailable" } as CloudUsageUnavailable))),
    ]);
    globalUsage = globalResult;
    visibleTasks.forEach((task, index) => {
      const result = summaryResults[index] ?? null;
      if (result && !isUsageUnavailable(result) && (result.taskId !== task.taskId || result.scope !== "task" || result.runId !== null)) {
        taskUsage.set(task.taskId, { kind: "unavailable", reason: "invalid" });
      } else {
        taskUsage.set(task.taskId, result);
      }
    });
  }

  const [liveSnapshot, githubStars] = await Promise.all([liveSnapshotPromise, getGitHubStars()]);
  return (
    <>
      <SiteHeader githubStars={githubStars} />
      <main id="content">
        <div className="mx-auto max-w-shell px-4 sm:px-8 lg:px-12">
          <header className="pt-10 sm:pt-12">
            <div>
              <p className="text-sm font-medium text-muted">Repository automation</p>
              <h1 className="mt-2 text-3xl font-medium leading-tight text-ink sm:text-4xl">Steward</h1>
              <p className="mt-3 max-w-3xl text-base leading-7 text-muted">Follow current control-loop state and public task history without hiding unavailable evidence.</p>
              <p className="mt-4 text-xs text-muted">
                <span className={`font-medium ${liveSnapshot?.availability === "live" ? "text-accent" : "text-muted"}`}>
                  {liveSnapshot ? `Live snapshot ${liveSnapshot.availability}` : "Live snapshot unavailable"}
                </span>
                {liveSnapshot ? (
                  <span className="mt-1 block data-text">
                    Daemon {titleCase(liveSnapshot.daemon.mode)} · observed {formatAge(liveSnapshot.observedAt)} · stale after {liveSnapshot.staleAfterSeconds}s
                  </span>
                ) : null}
              </p>
            </div>
            <ControlLoop activeView={activeView} liveSnapshot={liveSnapshot} historyPage={historyPage} />
          </header>
          {activeView === "signals" ? <LiveDomainView domain="signals" snapshot={liveSnapshot} /> : null}
          {activeView === "planning" ? <LiveDomainView domain="planning" snapshot={liveSnapshot} /> : null}
          {activeView === "tasks" ? <TasksView liveSnapshot={liveSnapshot} status={status} activePage={activePage} historyPage={historyPage} cursor={cursor} activeCursor={activeCursor} globalUsage={globalUsage} taskUsage={taskUsage} /> : null}
        </div>
      </main>
      <footer className="border-t border-line">
        <div className="mx-auto flex max-w-shell flex-col gap-3 px-4 py-8 text-xs text-muted sm:flex-row sm:items-center sm:justify-between sm:px-8 lg:px-12">
          <p>Read-only task publications. Missing values remain missing.</p>
          <a href="https://github.com/minhuw/coquic" className="inline-flex items-center gap-1.5 text-inherit hover:text-ink">minhuw/coquic<ExternalLink aria-hidden="true" size={13} /></a>
        </div>
      </footer>
    </>
  );
}

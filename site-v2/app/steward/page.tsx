import type { Metadata } from "next";
import { ExternalLink } from "lucide-react";
import Link from "next/link";
import { StewardFactory } from "@/components/steward-factory";
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

function LiveDomainView({ domain, snapshot }: { domain: "signals" | "planning"; snapshot: StewardLiveSnapshot | null }) {
  return <section className="py-10">
    <h2 className="text-2xl font-semibold">{titleCase(domain)} evidence</h2>
    <p className="mt-3 text-muted">{!snapshot ? "Live state is unavailable. Reload to try again. " : ""}{domain === "signals" ? "The public snapshot contains a pending count, not individual observations." : "The public snapshot contains planner state, not live plans or run history."} Planning records attached to published tasks remain available in the archive.</p>
    <Link className="mt-4 inline-block text-accent" href="/steward?view=tasks#steward-evidence">Published tasks →</Link>
  </section>;
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
  usage,
}: {
  task: CloudTaskSummary;
  usage: CloudUsageReadResult<CloudUsageSummary> | null;
}) {
  return (
    <li className="border-b border-line py-4">
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
  status,
  activePage,
  historyPage,
  cursor,
  activeCursor,
  globalUsage,
  taskUsage,
}: {
  status: CloudStatus | null;
  activePage: CloudTaskPage | null;
  historyPage: CloudTaskPage | null;
  cursor: string | null;
  activeCursor: string | null;
  globalUsage: CloudUsageGlobalGroup[] | CloudUsageUnavailable;
  taskUsage: ReadonlyMap<string, CloudUsageReadResult<CloudUsageSummary> | null>;
}) {
  const usageEvidence = isUsageUnavailable(globalUsage) ? <p className="mt-6 text-sm text-muted">Usage unavailable. Reload to try again.</p> : globalUsage.length > 0 ? <UsageEvidence usage={globalUsage} /> : null;
  const summary = <header className="flex flex-wrap items-baseline justify-between gap-3 border-b border-line pb-4">
    <h2 className="text-2xl font-semibold">Published tasks</h2>
    <p className="text-sm text-muted">Archive history: {historyPage?.total ?? "Unavailable"}{status?.latestPublicationAt && <> · Latest publication <time dateTime={status.latestPublicationAt}>{formatDateTime(status.latestPublicationAt)}</time></>}</p>
  </header>;
  if (!status || !activePage || !historyPage) {
    return (
      <div className="py-10 sm:py-12">
        {summary}
        <p className="mt-8 border-y border-line py-8 text-sm text-muted">
          Task archive unavailable. Reload to try again; live counts above are independent.
        </p>
        {usageEvidence}
      </div>
    );
  }

  const activeRows = activePage.tasks;
  const historyRows = historyPage.tasks;
  return <div className="py-10 sm:py-12">
    {summary}
    {activePage.total === 0 && historyPage.total === 0 && <p className="py-6 text-sm text-muted">No published tasks yet.</p>}
    {activePage.total > 0 && <section className="mt-6" aria-labelledby="active-tasks-title">
      <h3 id="active-tasks-title" className="text-lg font-semibold">Active tasks · {activePage.total}</h3>
      {activeRows.length > 0 && <ul>{activeRows.map((task) => <TaskRowView key={task.taskId} task={task} usage={taskUsage.get(task.taskId) ?? null} />)}</ul>}
      {activeRows.length === 0 && <p className="py-4 text-sm text-muted">No active tasks on this page.</p>}
      {(activePage.previousCursor || activePage.nextCursor) && <nav aria-label="Active task pages" className="mt-5 flex justify-between gap-4 text-sm text-accent">
        {activePage.previousCursor && <Link href={tasksHref(cursor, activePage.previousCursor)}>Previous active tasks</Link>}
        {activePage.nextCursor && <Link href={tasksHref(cursor, activePage.nextCursor)}>Next active tasks</Link>}
      </nav>}
    </section>}
    {historyPage.total > 0 && <section className="mt-6" aria-labelledby="task-history-title">
      <h3 id="task-history-title" className="text-lg font-semibold">Task history</h3>
      {historyRows.length > 0 && <ul>{historyRows.map((task) => <TaskRowView key={task.taskId} task={task} usage={taskUsage.get(task.taskId) ?? null} />)}</ul>}
      {historyRows.length === 0 && <p className="py-4 text-sm text-muted">No history tasks on this page.</p>}
      {(historyPage.previousCursor || historyPage.nextCursor) && <nav aria-label="Task history pages" className="mt-5 flex justify-between gap-4 text-sm text-accent">
        {historyPage.previousCursor && <Link href={tasksHref(historyPage.previousCursor, activeCursor)}>Previous page</Link>}
        {historyPage.nextCursor && <Link href={tasksHref(historyPage.nextCursor, activeCursor)}>Next page</Link>}
      </nav>}
    </section>}
    {usageEvidence}
  </div>;
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
        <StewardFactory snapshot={liveSnapshot} activeView={activeView} />
        <div id="steward-evidence" className="mx-auto max-w-shell px-4 sm:px-8 lg:px-12">
          {activeView === "signals" ? <LiveDomainView domain="signals" snapshot={liveSnapshot} /> : null}
          {activeView === "planning" ? <LiveDomainView domain="planning" snapshot={liveSnapshot} /> : null}
          {activeView === "tasks" ? <TasksView status={status} activePage={activePage} historyPage={historyPage} cursor={cursor} activeCursor={activeCursor} globalUsage={globalUsage} taskUsage={taskUsage} /> : null}
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

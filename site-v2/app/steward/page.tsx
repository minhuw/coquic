import type { Metadata } from "next";
import { ArrowRight, ExternalLink, GitBranch, Radio, Route, type LucideIcon } from "lucide-react";
import Link from "next/link";
import { SiteHeader } from "@/components/site-header";
import { getGitHubStars } from "@/lib/github";
import {
  getCloudRepository,
  type CloudTaskPage,
} from "@/lib/steward-archive/cloud-repository";
import type {
  CloudStatus,
  CloudTaskSummary,
} from "@/lib/steward-archive/cloud-schema";

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

function ControlLoop({
  activeView,
  status,
  activePage,
  historyPage,
}: {
  activeView: View;
  status: CloudStatus | null;
  activePage: CloudTaskPage | null;
  historyPage: CloudTaskPage | null;
}) {
  const taskDetail = status
    ? `${activePage?.total ?? "Unavailable"} active / ${historyPage?.total ?? "Unavailable"} history`
    : "not connected";
  const steps: readonly {
    id: View | null;
    label: string;
    value: string;
    detail: string;
    href: string;
    icon: LucideIcon;
  }[] = [
    {
      id: "signals",
      label: "Signals",
      value: "Unavailable",
      detail: "not published",
      href: "/steward?view=signals",
      icon: Radio,
    },
    {
      id: "planning",
      label: "Planning",
      value: "Unavailable",
      detail: "not published",
      href: "/steward?view=planning",
      icon: Route,
    },
    {
      id: "tasks",
      label: "Tasks",
      value: status ? String(status.taskCount) : "Unavailable",
      detail: taskDetail,
      href: "/steward?view=tasks",
      icon: GitBranch,
    },
    {
      id: null,
      label: "Integration",
      value: "Unavailable",
      detail: "not published",
      href: "/steward?view=tasks",
      icon: ArrowRight,
    },
  ];

  return (
    <section
      aria-label="Steward task channels"
      className="mt-9 border-y border-line bg-contrast-field text-contrast-ink"
    >
      <div className="grid sm:grid-cols-2 lg:grid-cols-4">
        {steps.map((step, index) => {
          const Icon = step.icon;
          const selected = step.id === activeView;
          return (
            <Link
              key={`${step.label}-${index}`}
              href={step.href}
              aria-current={selected ? "page" : undefined}
              className={`group relative min-w-0 border-contrast-line px-5 py-6 text-contrast-ink no-underline sm:px-6 ${index < 3 ? "border-b lg:border-b-0 lg:border-r" : ""} ${index === 0 ? "sm:border-r" : ""} ${index === 1 ? "lg:border-r" : ""}`}
            >
              <div className="flex items-center justify-between gap-4">
                <span className="flex items-center gap-2 text-sm font-medium text-contrast-muted">
                  <Icon aria-hidden="true" size={15} strokeWidth={1.7} />
                  {step.label}
                </span>
                {index < 3 ? <ArrowRight aria-hidden="true" size={14} className="text-contrast-muted" /> : null}
              </div>
              <p className="mt-5 flex flex-wrap items-baseline gap-2">
                <span className="text-2xl font-medium data-text">{step.value}</span>
                <span className="text-xs text-contrast-muted">{step.detail}</span>
              </p>
              {selected ? <span className="absolute inset-x-0 bottom-0 h-0.5 bg-accent" /> : null}
            </Link>
          );
        })}
      </div>
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
      <SectionOpening label="Cloud channel" title={title} description={description} />
      <p className="mt-8 border-y border-line py-8 text-sm text-muted">
        No local fallback or fixture records are displayed.
      </p>
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

function TaskRowView({ task, selected }: { task: CloudTaskSummary; selected: boolean }) {
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
}: {
  status: CloudStatus | null;
  activePage: CloudTaskPage | null;
  historyPage: CloudTaskPage | null;
  cursor: string | null;
  activeCursor: string | null;
}) {
  if (!status || !activePage || !historyPage) {
    return (
      <UnavailableView
        title="Cloud task overview unavailable"
        description="The public task status or collection is temporarily unavailable."
      />
    );
  }

  const activeRows = activePage.tasks;
  const historyRows = historyPage.tasks;
  const selectedTask = activeRows[0] ?? historyRows[0] ?? null;
  return (
    <div className="py-10 sm:py-12">
      <SectionOpening
        label="Cloud task archive"
        title="Every visible task publication"
        description="Active work and completed history come from the public cloud collections. Each task links to its validated detail view."
      />
      <div className="mt-8 grid grid-cols-2 border-y border-line sm:grid-cols-4">
        {[
          ["Visible tasks", status.taskCount],
          ["Active", activePage.total],
          ["History", historyPage.total],
          ["Latest publication", formatDateTime(status.latestPublicationAt)],
        ].map(([label, value], index) => (
          <div key={String(label)} className={`px-4 py-4 ${index < 3 ? "border-r border-line" : ""}`}>
            <dt className="text-xs text-muted">{label}</dt>
            <dd className="mt-1 text-lg font-medium text-ink data-text">{value}</dd>
          </div>
        ))}
      </div>
      <section className="mt-8 border-y border-line xl:grid xl:grid-cols-[17rem_minmax(0,1fr)_19rem]" aria-labelledby="task-list-title">
        <div className="py-6 xl:border-r xl:border-line xl:pr-6">
          <div className="flex items-baseline justify-between gap-4">
            <h3 id="task-list-title" className="text-lg font-semibold text-ink">Active tasks</h3>
            <span className="text-xs text-muted data-text">{activePage.total}</span>
          </div>
          <ul className="mt-4 border-t border-line">
            {activeRows.map((task) => <TaskRowView key={task.taskId} task={task} selected={task.taskId === selectedTask?.taskId} />)}
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
            {historyRows.map((task) => <TaskRowView key={task.taskId} task={task} selected={task.taskId === selectedTask?.taskId} />)}
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
  let status: CloudStatus | null = null;
  let activePage: CloudTaskPage | null = null;
  let historyPage: CloudTaskPage | null = null;

  try {
    const repository = getCloudRepository();
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

  const githubStars = await getGitHubStars();
  return (
    <>
      <SiteHeader githubStars={githubStars} />
      <main id="content">
        <div className="mx-auto max-w-shell px-4 sm:px-8 lg:px-12">
          <header className="pt-10 sm:pt-12">
            <div className="grid gap-5 lg:grid-cols-[minmax(0,1fr)_auto] lg:items-end">
              <div>
                <p className="text-sm font-medium text-muted">Repository automation</p>
                <h1 className="mt-2 text-3xl font-medium leading-tight text-ink sm:text-4xl">Steward</h1>
                <p className="mt-3 max-w-3xl text-base leading-7 text-muted">Follow the public task publications without hiding partial work.</p>
              </div>
              <p className="text-xs text-muted lg:text-right">
                <span className="font-medium text-accent">Cloud archive</span>
                <span className="mt-1 block data-text">{formatDateTime(status?.latestPublicationAt ?? null)}</span>
              </p>
            </div>
            <ControlLoop activeView={activeView} status={status} activePage={activePage} historyPage={historyPage} />
          </header>
          {activeView === "signals" ? (
            <UnavailableView title="Signals unavailable" description="The initial public cloud contract does not publish a global signal domain." />
          ) : null}
          {activeView === "planning" ? (
            <UnavailableView title="Planning unavailable" description="The initial public cloud contract does not publish global planning evidence." />
          ) : null}
          {activeView === "tasks" ? <TasksView status={status} activePage={activePage} historyPage={historyPage} cursor={cursor} activeCursor={activeCursor} /> : null}
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

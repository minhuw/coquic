import type { Metadata } from "next";
import {
  ArrowRight,
  ExternalLink,
  GitBranch,
  Radio,
  Route,
} from "lucide-react";
import Link from "next/link";
import { SiteHeader } from "@/components/site-header";
import activeTaskDetail from "@/examples/steward-active-task-detail.json";
import snapshot from "@/examples/steward-control-loop.json";
import { getGitHubStars } from "@/lib/github";

export const metadata: Metadata = {
  title: "Steward",
  description: "Inspect the public evidence behind CoQUIC repository automation.",
};

export const revalidate = 60;

const views = ["signals", "planning", "tasks"] as const;
type View = (typeof views)[number];

const data = snapshot.data;
const activeTask = activeTaskDetail.data;
const stageLabels = ["Plan", "Implement", "Validate", "Review", "Integrate"];

function titleCase(value: string) {
  return value
    .replace(/([A-Z])/g, " $1")
    .replace(/[._-]/g, " ")
    .replace(/^./, (letter) => letter.toUpperCase());
}

function formatDateTime(value: string) {
  return new Intl.DateTimeFormat("en-US", {
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
    timeZone: "UTC",
    timeZoneName: "short",
  }).format(new Date(value));
}

function Status({ value }: { value: string }) {
  const tone =
    value === "running" || value === "active"
      ? "text-accent"
      : value === "pushed" || value === "planned" || value === "ready"
        ? "text-positive"
        : value === "blocked" || value === "error"
          ? "text-negative"
          : value === "pending" || value === "due"
            ? "text-warning"
            : "text-muted";
  return <span className={`font-medium ${tone}`}>{titleCase(value)}</span>;
}

function ControlLoop({ activeView }: { activeView: View }) {
  const steps = [
    {
      id: "signals" as const,
      label: "Signals",
      value: data.counts.pendingSignals,
      detail: `pending of ${data.counts.signals}`,
      icon: Radio,
    },
    {
      id: "planning" as const,
      label: "Planning",
      value: data.counts.plannerRuns,
      detail: "published runs",
      icon: Route,
    },
    {
      id: "tasks" as const,
      label: "Tasks",
      value: data.counts.active + data.counts.queued,
      detail: `${data.counts.active} active · ${data.counts.queued} queued`,
      icon: GitBranch,
    },
    {
      id: "tasks" as const,
      label: "Integration",
      value: data.counts.attention,
      detail: "need attention",
      icon: ArrowRight,
    },
  ];

  return (
    <section aria-label="Steward control loop" className="mt-9 border-y border-line bg-contrast-field text-contrast-ink">
      <div className="grid sm:grid-cols-2 lg:grid-cols-4">
        {steps.map((step, index) => {
          const Icon = step.icon;
          const selected = index < 3 && step.id === activeView;
          return (
            <Link
              key={`${step.label}-${index}`}
              href={`/steward?view=${step.id}`}
              aria-current={selected ? "page" : undefined}
              className={`group relative min-w-0 border-contrast-line px-5 py-6 text-contrast-ink no-underline sm:px-6 ${
                index < 3 ? "border-b lg:border-b-0 lg:border-r" : ""
              } ${index === 0 ? "sm:border-r" : ""} ${index === 1 ? "lg:border-r" : ""}`}
            >
              <div className="flex items-center justify-between gap-4">
                <span className="flex items-center gap-2 text-sm font-medium text-contrast-muted">
                  <Icon aria-hidden="true" size={15} strokeWidth={1.7} />
                  {step.label}
                </span>
                {index < 3 ? (
                  <ArrowRight aria-hidden="true" size={14} className="text-contrast-muted transition-transform group-hover:translate-x-1 motion-reduce:transition-none" />
                ) : null}
              </div>
              <p className="mt-5 flex items-baseline gap-2">
                <span className="text-3xl font-medium data-text">{step.value}</span>
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

function SectionOpening({ label, title, description }: { label: string; title: string; description: string }) {
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

function SignalsView() {
  const pending = data.signals.filter((signal) => signal.status === "pending");
  const scheduled = data.signals.filter((signal) => signal.status === "planned");
  return (
    <div id="signals-panel" className="py-10 sm:py-12">
      <SectionOpening
        label="Source intake"
        title="Evidence waiting for a decision"
        description="Signals retain the source, severity, and exact context the planner receives. Pending evidence is kept separate from work already scheduled."
      />

      <div className="mt-8 border-y border-line xl:grid xl:grid-cols-[16rem_minmax(0,1.25fr)_minmax(20rem,0.75fr)]">
        <section className="py-6 xl:border-r xl:border-line xl:pr-6" aria-labelledby="providers-title">
          <h3 id="providers-title" className="text-lg font-semibold text-ink">Providers</h3>
          <p className="mt-2 text-xs leading-5 text-muted">Fetch state and latest result</p>
          <ul className="mt-4 border-t border-line">
            {data.providers.map((provider) => (
              <li key={provider.id} className="border-b border-line py-4">
                <div className="flex items-baseline justify-between gap-3"><p className="break-words text-xs font-medium text-ink data-text">{provider.id}</p><span className="text-xs"><Status value={provider.state} /></span></div>
                <p className="mt-2 text-xs leading-5 text-muted">{provider.error ?? provider.summary}</p>
                <time className="mt-2 block text-xs text-faint data-text" dateTime={provider.lastFetchAt}>{formatDateTime(provider.lastFetchAt)}</time>
              </li>
            ))}
          </ul>
        </section>

        <section className="py-6 xl:px-7" aria-labelledby="pending-signals-title">
          <div className="flex items-baseline justify-between gap-5">
            <h3 id="pending-signals-title" className="text-lg font-semibold text-ink">Pending signals</h3>
            <span className="text-xs text-warning data-text">{data.counts.pendingSignals} total · {pending.length} shown</span>
          </div>
          <SignalList signals={pending} />
        </section>

        <section className="py-6 xl:border-l xl:border-line xl:pl-6" aria-labelledby="scheduled-signals-title">
          <div className="flex items-baseline justify-between gap-5">
            <h3 id="scheduled-signals-title" className="text-lg font-semibold text-ink">Scheduled</h3>
            <span className="text-xs text-muted">{scheduled.length}</span>
          </div>
          <SignalList signals={scheduled} />
        </section>
      </div>
    </div>
  );
}

function SignalList({ signals }: { signals: typeof data.signals }) {
  return (
    <ul className="mt-5 border-t border-line">
      {signals.map((signal) => (
        <li key={signal.id} className="border-b border-line py-5">
          <div className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1 text-xs">
            <span className="break-words text-muted data-text">{signal.provider}</span>
            <Status value={signal.status} />
          </div>
          <h4 className="mt-2 text-sm font-semibold leading-5 text-ink">{signal.title}</h4>
          <p className="mt-2 text-xs leading-5 text-muted">{signal.summary}</p>
          <dl className="mt-3 grid gap-x-4 gap-y-2 sm:grid-cols-3 xl:grid-cols-1 2xl:grid-cols-3">
            {signal.context.map((item) => <div key={item.label} className="min-w-0"><dt className="text-xs text-faint">{item.label}</dt><dd className="mt-0.5 break-words text-xs text-ink data-text">{item.value}</dd></div>)}
          </dl>
          <div className="mt-4 flex flex-wrap items-center gap-x-4 gap-y-2 text-xs">
            {signal.links.map((link) => <a key={link.url} href={link.url} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 text-accent no-underline">{link.label}<ExternalLink aria-hidden="true" size={12} /></a>)}
            {signal.plannerRunId ? <Link href="/steward?view=planning" className="font-medium text-accent no-underline">Planner decision</Link> : <span className="text-warning">Awaiting planner</span>}
          </div>
          {signal.plannedTaskId ? <Link href={`/steward/tasks/${signal.plannedTaskId}`} className="mt-2 block break-all text-xs text-accent no-underline data-text">{signal.plannedTaskId}</Link> : null}
        </li>
      ))}
    </ul>
  );
}

function PlanningView() {
  const selectedRun = data.plannerRuns[0];
  return (
    <div id="planning-panel" className="py-10 sm:py-12">
      <SectionOpening
        label="Scheduling"
        title="How evidence becomes bounded work"
        description="Each planner run preserves its inputs, proposed tasks, canonical counters, diagnostics, and transcript availability. Publication inconsistencies remain visible."
      />

      <div className="mt-8 border-y border-line xl:grid xl:grid-cols-[17rem_minmax(0,1fr)_19rem]">
      <section className="py-6 xl:border-r xl:border-line xl:pr-6" aria-labelledby="wakeups-title">
        <div><h3 id="wakeups-title" className="text-lg font-semibold text-ink">Pending wakeups</h3><p className="mt-2 text-xs leading-5 text-muted">Events waiting to trigger another scheduling cycle.</p></div>
        <ol className="border-t border-line">
          {data.wakeups.map((wakeup) => (
            <li key={wakeup.id} className="border-b border-line py-4">
              <div className="flex items-baseline justify-between gap-3"><span className="text-xs font-medium text-warning">{titleCase(wakeup.reason)}</span><time className="text-xs text-muted data-text" dateTime={wakeup.createdAt}>{formatDateTime(wakeup.createdAt)}</time></div>
              <p className="mt-2 text-sm leading-5 text-ink">{wakeup.context}</p>
              <Link href={`/steward/tasks/${wakeup.taskId}`} className="mt-1 block break-all text-xs text-accent no-underline data-text">{wakeup.taskId}</Link>
            </li>
          ))}
        </ol>
      </section>

      <section className="min-w-0 py-6 xl:px-7" aria-labelledby="planner-runs-title">
        <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
          <div><p className="text-xs font-medium text-accent">Selected planner run</p><h3 id="planner-runs-title" className="mt-2 break-all text-lg font-semibold text-ink data-text">{selectedRun.id}</h3><time className="mt-2 block text-xs text-muted data-text" dateTime={selectedRun.startedAt}>{formatDateTime(selectedRun.startedAt)}</time></div>
          <Status value={selectedRun.status} />
        </div>

        <dl className="mt-5 grid grid-cols-2 border-y border-line sm:grid-cols-4">
          {[["Input signals", selectedRun.consumedSignals.length], ["Output proposals", selectedRun.proposedTasks.length], ["Canonical proposed", selectedRun.canonicalCounts.proposed], ["Canonical accepted", selectedRun.canonicalCounts.accepted]].map(([label, value], index) => <div key={String(label)} className={`px-3 py-4 ${index < 3 ? "border-r border-line" : ""}`}><dt className="text-xs text-muted">{label}</dt><dd className="mt-1 text-xl font-medium data-text">{value}</dd></div>)}
        </dl>

        <div className="mt-6">
          <h4 className="text-sm font-semibold text-ink">Proposed work</h4>
          <ul className="mt-2 border-t border-line">
            {selectedRun.proposedTasks.map((task) => <li key={task.id} className="grid gap-2 border-b border-line py-4 sm:grid-cols-[minmax(0,1fr)_8rem] sm:gap-5"><div><p className="text-sm font-medium leading-5 text-ink">{task.title}</p><Link className="mt-1 block break-all text-xs text-accent no-underline data-text" href={`/steward/tasks/${task.id}`}>{task.id}</Link></div><div className="text-xs text-muted sm:text-right"><span className="block text-positive">Accepted</span><span className="mt-1 block data-text">{task.worker}</span></div></li>)}
          </ul>
        </div>
      </section>

      <aside className="py-6 xl:border-l xl:border-line xl:pl-6" aria-label="Planner diagnostics">
        <div className="flex items-baseline justify-between gap-3"><h3 className="text-lg font-semibold text-ink">Diagnostics</h3><span className="text-xs text-warning">Incomplete</span></div>
        <p className="mt-4 border-l-2 border-warning pl-4 text-sm leading-6 text-muted"><strong className="font-medium text-warning">Producer state.</strong> {selectedRun.diagnostic}</p>
        <dl className="mt-6 border-t border-line text-xs">
          <div className="flex justify-between border-b border-line py-3"><dt className="text-muted">Transcript</dt><dd className="text-ink">{titleCase(selectedRun.transcript.mode)}</dd></div>
          <div className="flex justify-between border-b border-line py-3"><dt className="text-muted">Size</dt><dd className="text-ink data-text">{selectedRun.transcript.sizeBytes.toLocaleString("en-US")} B</dd></div>
          <div className="flex justify-between border-b border-line py-3"><dt className="text-muted">Truncated</dt><dd className="text-ink">{selectedRun.transcript.truncated ? "Yes" : "No"}</dd></div>
          <div className="flex justify-between border-b border-line py-3"><dt className="text-muted">Retained runs</dt><dd className="text-ink data-text">{data.counts.plannerRuns}</dd></div>
        </dl>
        <h4 className="mt-7 text-sm font-semibold text-ink">Recent runs</h4>
        <ol className="mt-2 border-t border-line">
          {data.plannerRuns.map((run) => <li key={run.id} className="border-b border-line py-3"><div className="flex items-baseline justify-between gap-3"><Status value={run.status} /><span className="text-xs text-muted data-text">{run.proposedTasks.length} tasks</span></div><p className="mt-1 break-all text-xs text-faint data-text">{run.id}</p></li>)}
        </ol>
        <p className="mt-4 text-xs text-warning">Published window is truncated.</p>
      </aside>
      </div>
    </div>
  );
}

function TaskPipeline({ states }: { states: string[] }) {
  const compactLabels = ["Plan", "Code", "Test", "Review", "Merge"];
  return (
    <ol className="grid grid-cols-5" aria-label="Task pipeline">
      {states.map((state, index) => (
        <li key={stageLabels[index]} className="relative min-w-0">
          <span className={`block h-1 ${state === "complete" ? "bg-positive" : state === "active" ? "bg-accent" : state === "blocked" ? "bg-negative" : "bg-line-strong"}`} />
          <span className={`mt-2 block text-xs ${state === "active" ? "font-medium text-accent" : state === "blocked" ? "font-medium text-negative" : "text-muted"}`}>{compactLabels[index]}</span>
        </li>
      ))}
    </ol>
  );
}

function TasksView() {
  return (
    <div id="tasks-panel" className="py-10 sm:py-12">
      <SectionOpening
        label="Execution"
        title="Every task, from plan to integration"
        description="Open a task to inspect its stage graph, feedback loops, attempts, messages, tool calls, patch, validation, review findings, and ordered event history."
      />
      <div className="mt-7 grid grid-cols-2 border-y border-line sm:grid-cols-4">
        {[["Active", data.counts.active], ["Queued", data.counts.queued], ["Need attention", data.counts.attention], ["Retained", data.counts.tasks]].map(([label, value], index) => <div key={String(label)} className={`px-4 py-4 ${index < 3 ? "border-r border-line" : ""}`}><dt className="text-xs text-muted">{label}</dt><dd className="mt-1 text-xl font-medium text-ink data-text">{value}</dd></div>)}
      </div>

      <section className="mt-8 border-y border-line xl:grid xl:grid-cols-[17rem_minmax(0,1fr)_19rem]" aria-labelledby="task-list-title">
        <div className="py-6 xl:border-r xl:border-line xl:pr-6">
          <div className="flex items-baseline justify-between gap-4">
            <h3 id="task-list-title" className="text-lg font-semibold text-ink">Execution queue</h3>
            <span className="text-xs text-muted data-text">{data.tasks.length}</span>
          </div>
          <ul className="mt-4 border-t border-line">
          {data.tasks.map((task) => (
            <li key={task.id} className={`border-b border-line py-4 ${task.id === activeTask.task.id ? "border-l-2 border-l-accent pl-4" : ""}`}>
              <div className="flex items-baseline justify-between gap-3 text-xs">
                <Status value={task.status} />
                <span className="text-muted">{titleCase(task.kind)}</span>
              </div>
              {task.detailAvailable ? <Link href={`/steward/tasks/${task.id}`} className="mt-2 block text-sm font-semibold leading-5 text-ink no-underline hover:text-accent">{task.title}</Link> : <p className="mt-2 text-sm font-semibold leading-5 text-ink">{task.title}</p>}
              <div className="mt-3"><TaskPipeline states={task.stages} /></div>
            </li>
          ))}
          </ul>
        </div>

        <div className="min-w-0 py-6 xl:px-7">
          <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
            <div className="min-w-0">
              <p className="text-xs font-medium text-accent">Selected execution · active</p>
              <h3 className="mt-2 text-xl font-semibold leading-tight text-ink">{activeTask.task.title}</h3>
              <p className="mt-2 text-sm leading-6 text-muted">{activeTask.task.summary}</p>
            </div>
            <Link href={`/steward/tasks/${activeTask.task.id}`} className="inline-flex shrink-0 items-center gap-1.5 text-sm font-medium text-accent no-underline">
              Full evidence <ArrowRight aria-hidden="true" size={14} />
            </Link>
          </div>

          <div className="mt-6 bg-contrast-field px-5 py-5 text-contrast-ink">
            <ol className="grid grid-cols-5" aria-label="Selected task execution pipeline">
              {activeTask.pipeline.stages.map((stage, index) => (
                <li key={stage.id} className="min-w-0 pr-2">
                  <div className="flex items-center"><span className={`size-2.5 shrink-0 rounded-full ${stage.state === "complete" ? "bg-positive" : stage.state === "active" ? "bg-accent" : "border border-contrast-line"}`} />{index < 4 ? <span className="h-px flex-1 bg-contrast-line" /> : null}</div>
                  <p className="mt-2 text-xs font-medium">{stage.label}</p>
                  <p className="mt-1 hidden text-xs leading-4 text-contrast-muted sm:block">{stage.detail}</p>
                </li>
              ))}
            </ol>
          </div>

          <div className="mt-6 grid gap-6 lg:grid-cols-[minmax(0,1fr)_12rem]">
            <div>
              <h4 className="text-sm font-semibold text-ink">Latest agent activity</h4>
              <ol className="mt-3 border-t border-line">
                {activeTask.transcript.slice(-3).map((item) => (
                  <li key={item.id} className="grid grid-cols-[6rem_minmax(0,1fr)] gap-4 border-b border-line py-3">
                    <span className="text-xs text-muted">{item.label}</span>
                    <p className="line-clamp-2 text-xs leading-5 text-ink">{"text" in item ? item.text : "command" in item ? item.command : "Published event"}</p>
                  </li>
                ))}
              </ol>
            </div>
            <dl className="border-t border-line text-xs">
              <div className="flex justify-between border-b border-line py-3"><dt className="text-muted">Worker events</dt><dd className="text-ink data-text">{activeTask.attempts[0].workerRun.events}</dd></div>
              <div className="flex justify-between border-b border-line py-3"><dt className="text-muted">Changed paths</dt><dd className="text-ink data-text">23</dd></div>
              <div className="flex justify-between border-b border-line py-3"><dt className="text-muted">Transcript</dt><dd className="text-ink data-text">49.5 KB</dd></div>
              <div className="flex justify-between border-b border-line py-3"><dt className="text-muted">Validation</dt><dd className="text-warning">Pending</dd></div>
            </dl>
          </div>
        </div>

        <aside className="py-6 xl:border-l xl:border-line xl:pl-6" aria-label="Current task evidence">
          <div className="flex items-baseline justify-between gap-4"><h3 className="text-lg font-semibold text-ink">Current evidence</h3><span className="text-xs text-warning">Partial</span></div>
          <ol className="mt-4 border-t border-line">
            {activeTask.timeline.slice().reverse().map((event) => (
              <li key={event.id} className="border-b border-line py-4">
                <div className="flex items-baseline justify-between gap-3"><p className="text-sm font-medium text-ink">{event.title}</p><span className="text-xs text-muted">{titleCase(event.stage)}</span></div>
                <p className="mt-2 text-xs leading-5 text-muted">{event.detail}</p>
                <time className="mt-2 block text-xs text-faint data-text" dateTime={event.timestamp}>{formatDateTime(event.timestamp)}</time>
              </li>
            ))}
          </ol>
          <p className="mt-4 text-xs leading-5 text-warning">Patch, validation, review, and integration evidence have not been published.</p>
        </aside>
      </section>
    </div>
  );
}

interface StewardPageProps { searchParams: Promise<Record<string, string | string[] | undefined>> }

export default async function StewardPage({ searchParams }: StewardPageProps) {
  const params = await searchParams;
  const requested = typeof params.view === "string" ? params.view : "tasks";
  const activeView: View = views.includes(requested as View) ? requested as View : "tasks";
  const githubStars = await getGitHubStars();

  return (
    <>
      <SiteHeader githubStars={githubStars} />
      <main id="content">
        <div className="mx-auto max-w-shell px-4 sm:px-8 lg:px-12">
          <header className="pt-10 sm:pt-12">
            <div className="grid gap-5 lg:grid-cols-[minmax(0,1fr)_auto] lg:items-end">
              <div><p className="text-sm font-medium text-muted">Repository automation</p><h1 className="mt-2 text-3xl font-medium leading-tight text-ink sm:text-4xl">Steward</h1><p className="mt-3 max-w-3xl text-base leading-7 text-muted">Follow the complete public control loop: what Steward notices, how it decides, and what every worker does next.</p></div>
              <p className="text-xs text-muted lg:text-right"><span className="font-medium text-warning">Historic snapshot</span><time className="mt-1 block data-text" dateTime={snapshot.generatedAt}>{formatDateTime(snapshot.generatedAt)}</time><span className="mt-1 block data-text">{data.repository} / {data.mainBranch}</span></p>
            </div>
            <ControlLoop activeView={activeView} />
          </header>

          {activeView === "signals" ? <SignalsView /> : null}
          {activeView === "planning" ? <PlanningView /> : null}
          {activeView === "tasks" ? <TasksView /> : null}
        </div>
      </main>
      <footer className="border-t border-line"><div className="mx-auto flex max-w-shell flex-col gap-3 px-4 py-8 text-xs text-muted sm:flex-row sm:items-center sm:justify-between sm:px-8 lg:px-12"><p>Read-only sanitized evidence. Publication gaps are shown explicitly.</p><a href="https://github.com/minhuw/coquic" className="inline-flex items-center gap-1.5 text-inherit hover:text-ink">minhuw/coquic<ExternalLink aria-hidden="true" size={13} strokeWidth={1.8} /></a></div></footer>
    </>
  );
}

import type { Metadata } from "next";
import { ArrowLeft, ExternalLink, FileDown, RefreshCw, ShieldAlert } from "lucide-react";
import Link from "next/link";
import { notFound } from "next/navigation";
import { SiteHeader } from "@/components/site-header";
import { getGitHubStars } from "@/lib/github";
import {
  getCloudRepository,
} from "@/lib/steward-archive/cloud-repository";
import type { CloudTaskDetail } from "@/lib/steward-archive/cloud-schema";
import {
  buildCloudTaskViewModel,
  type CloudArtifactView,
  type CloudPipelineView,
  type CloudRunView,
  type CloudTaskViewModel,
} from "@/lib/steward-archive/cloud-view-model";
import { TimelineDrawer } from "./timeline-drawer";

export const metadata: Metadata = { title: "Steward task" };
export const dynamic = "force-dynamic";
export const revalidate = 0;

function titleCase(value: string) {
  return value.replace(/([A-Z])/g, " $1").replace(/[._-]/g, " ").replace(/^./, (letter) => letter.toUpperCase());
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

function formatBytes(value: number) {
  if (value >= 1_000_000) return `${(value / 1_000_000).toFixed(1).replace(/\.0$/, "")} MB`;
  if (value >= 1_000) return `${(value / 1_000).toFixed(value >= 100_000 ? 0 : 1).replace(/\.0$/, "")} KB`;
  return `${value} B`;
}

function formatDuration(durationMs: number | null) {
  if (durationMs === null) return "Unavailable";
  if (durationMs < 1_000) return `${durationMs} ms`;
  const seconds = durationMs / 1_000;
  return `${seconds.toFixed(seconds % 1 === 0 ? 0 : 1)} s`;
}

function statusTone(value: string) {
  if (value === "active" || value === "available") return "text-accent";
  if (value === "completed") return "text-positive";
  if (value === "failed" || value === "cancelled") return "text-negative";
  return "text-muted";
}

function Status({ value }: { value: string }) {
  return <span className={`font-medium ${statusTone(value)}`}>{titleCase(value)}</span>;
}

function taskHref(taskId: string, query: Record<string, string | undefined> = {}) {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query)) if (value) params.set(key, value);
  const suffix = params.toString();
  return `/steward/tasks/${encodeURIComponent(taskId)}${suffix ? `?${suffix}` : ""}`;
}

function pipelineHref(taskId: string, pipelineId: string) {
  return `${taskHref(taskId, { pipeline: pipelineId })}#pipeline-${encodeURIComponent(pipelineId)}`;
}

function runHref(taskId: string, pipelineId: string, runId: string) {
  return `${taskHref(taskId, { pipeline: pipelineId, run: runId })}#run-${encodeURIComponent(runId)}`;
}

function artifactHref(taskId: string, artifact: CloudArtifactView) {
  if (!artifact.action) return null;
  return `/api/steward/tasks/${encodeURIComponent(taskId)}/artifact?path=${encodeURIComponent(artifact.action.logicalPath)}`;
}

function Disclosure({ redactionApplied, originalRetained }: { redactionApplied: boolean; originalRetained: boolean }) {
  return (
    <span className="inline-flex items-center gap-1.5 text-xs text-muted">
      <ShieldAlert aria-hidden="true" size={13} />
      {redactionApplied ? "Public values redacted" : "Public values unchanged"}
      <span className="text-faint">·</span>
      {originalRetained ? "Original retained" : "Original unavailable"}
    </span>
  );
}

function TaskUnavailable({ taskId, githubStars }: { taskId: string; githubStars: number | null }) {
  return (
    <>
      <SiteHeader githubStars={githubStars} />
      <main id="content">
        <div className="mx-auto max-w-shell px-4 sm:px-8 lg:px-12">
          <section className="py-16 sm:py-20" aria-labelledby="task-unavailable-title">
            <p className="text-sm font-medium text-muted">Cloud task detail</p>
            <h1 id="task-unavailable-title" className="mt-2 text-3xl font-medium leading-tight text-ink sm:text-4xl">Task detail unavailable</h1>
            <p className="mt-4 max-w-2xl text-base leading-7 text-muted">The public cloud task detail could not be read right now. No local records are used as a fallback.</p>
            <Link href={taskHref(taskId)} className="mt-7 inline-flex items-center gap-2 text-sm font-medium text-accent no-underline">
              Retry task detail
              <RefreshCw aria-hidden="true" size={14} />
            </Link>
          </section>
        </div>
      </main>
      <footer className="border-t border-line"><div className="mx-auto max-w-shell px-4 py-8 text-xs text-muted sm:px-8 lg:px-12">Read-only task publications. Missing values remain missing.</div></footer>
    </>
  );
}

function TaskHeader({ model }: { model: CloudTaskViewModel }) {
  const { task } = model;
  return (
    <header className="py-10 sm:py-12">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <Link href="/steward?view=tasks" className="inline-flex items-center gap-2 text-sm font-medium text-muted no-underline hover:text-ink"><ArrowLeft aria-hidden="true" size={15} />All tasks</Link>
        <span className="break-all text-xs text-faint data-text sm:text-right">{task.id}</span>
      </div>
      <div className="mt-7 grid gap-7 lg:grid-cols-[minmax(0,1fr)_22rem] lg:items-start">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-x-3 gap-y-2 text-sm"><Status value={task.status} /><span className="text-muted">Public cloud task</span></div>
          <h1 className="mt-3 max-w-4xl text-3xl font-medium leading-tight text-ink [overflow-wrap:anywhere] sm:text-4xl">{task.title}</h1>
          <p className="mt-4 max-w-3xl text-sm leading-6 text-muted">Immutable evidence for the published task graph. Values absent from the public contract remain unavailable.</p>
          <div className="mt-4"><Disclosure {...task.disclosure} /></div>
        </div>
        <dl className="border-t border-line text-xs">
          <div className="flex justify-between gap-4 border-b border-line py-3"><dt className="text-muted">Created</dt><dd className="text-right text-ink data-text">{formatDateTime(task.createdAt)}</dd></div>
          <div className="flex justify-between gap-4 border-b border-line py-3"><dt className="text-muted">Completed</dt><dd className="text-right text-ink data-text">{formatDateTime(task.completedAt)}</dd></div>
          <div className="flex justify-between gap-4 border-b border-line py-3"><dt className="text-muted">Pipelines</dt><dd className="text-ink data-text">{model.pipelines.length}</dd></div>
          <div className="flex justify-between gap-4 border-b border-line py-3"><dt className="text-muted">Runs</dt><dd className="text-ink data-text">{model.runs.length}</dd></div>
          <div className="flex justify-between gap-4 border-b border-line py-3"><dt className="text-muted">Events</dt><dd className="text-ink data-text">{model.events.length}</dd></div>
          <div className="flex justify-between gap-4 border-b border-line py-3"><dt className="text-muted">Artifacts</dt><dd className="text-ink data-text">{model.artifacts.length}</dd></div>
          <div className="flex justify-between gap-4 py-3"><dt className="text-muted">Publication</dt><dd className="text-right text-ink">Complete graph</dd></div>
        </dl>
      </div>
    </header>
  );
}

function PipelineRow({ taskId, pipeline, selected, selectedRunId }: { taskId: string; pipeline: CloudPipelineView; selected: boolean; selectedRunId: string | null }) {
  return (
    <article id={`pipeline-${encodeURIComponent(pipeline.pipelineId)}`} className={`scroll-mt-20 border-b border-line py-5 last:border-b-0 ${selected ? "border-l-2 border-l-accent pl-4" : ""}`}>
      <div className="flex flex-col gap-2 sm:flex-row sm:items-baseline sm:justify-between">
        <Link href={pipelineHref(taskId, pipeline.pipelineId)} aria-current={selected ? "page" : undefined} className="break-words text-base font-semibold text-ink no-underline hover:text-accent">{pipeline.name}</Link>
        <span className="text-xs text-muted data-text">{pipeline.runIds.length} {pipeline.runIds.length === 1 ? "run" : "runs"}</span>
      </div>
      <dl className="mt-3 grid gap-x-6 gap-y-2 text-xs text-muted sm:grid-cols-2"><div><dt className="inline">Pipeline ID </dt><dd className="inline break-all text-ink data-text">{pipeline.pipelineId}</dd></div><div><dt className="inline">Created </dt><dd className="inline text-ink data-text">{formatDateTime(pipeline.createdAt)}</dd></div></dl>
      {pipeline.runIds.length ? <ul className="mt-4 border-t border-line">{pipeline.runIds.map((runId) => <li key={runId} className="border-b border-line py-3 last:border-b-0"><Link href={runHref(taskId, pipeline.pipelineId, runId)} aria-current={selectedRunId === runId ? "page" : undefined} className={`inline-flex break-all text-sm no-underline ${selectedRunId === runId ? "font-semibold text-accent" : "font-medium text-ink hover:text-accent"}`}>{runId}</Link></li>)}</ul> : <p className="mt-4 text-sm text-muted">No runs are published for this pipeline.</p>}
    </article>
  );
}

function Pipelines({ model, taskId, selectedPipelineId, selectedRunId }: { model: CloudTaskViewModel; taskId: string; selectedPipelineId: string | null; selectedRunId: string | null }) {
  return (
    <section id="pipelines" aria-labelledby="pipelines-title" className="border-y border-line py-8 sm:py-10">
      <div className="flex items-baseline justify-between gap-4"><h2 id="pipelines-title" className="text-lg font-semibold text-ink">Pipelines</h2><span className="text-xs text-muted data-text">{model.pipelines.length}</span></div>
      <p className="mt-3 max-w-3xl text-sm leading-6 text-muted">Each published pipeline links to the runs it owns. Select a run to inspect its immutable public metadata and artifacts.</p>
      <div className="mt-5 border-t border-line">{model.pipelines.length ? model.pipelines.map((pipeline) => <PipelineRow key={pipeline.pipelineId} taskId={taskId} pipeline={pipeline} selected={pipeline.pipelineId === selectedPipelineId} selectedRunId={selectedRunId} />) : <p className="py-6 text-sm text-muted">No pipelines are published for this task.</p>}</div>
    </section>
  );
}

function RunEvidence({ taskId, run, selected }: { taskId: string; run: CloudRunView; selected: boolean }) {
  return (
    <article id={`run-${encodeURIComponent(run.runId)}`} className={`scroll-mt-20 border-b border-line py-5 last:border-b-0 ${selected ? "border-l-2 border-l-accent pl-4" : ""}`}>
      <div className="flex flex-col gap-2 sm:flex-row sm:items-baseline sm:justify-between"><Link href={runHref(taskId, run.pipelineId, run.runId)} aria-current={selected ? "page" : undefined} className={`break-all text-sm font-semibold no-underline ${selected ? "text-accent" : "text-ink hover:text-accent"}`}>{run.runId}</Link><Status value={run.status} /></div>
      <dl className="mt-3 grid gap-x-6 gap-y-2 text-xs text-muted sm:grid-cols-2 lg:grid-cols-4"><div><dt className="inline">Role </dt><dd className="inline text-ink">{titleCase(run.role)}</dd></div><div><dt className="inline">Pipeline </dt><dd className="inline break-all text-ink data-text">{run.pipelineId}</dd></div><div><dt className="inline">Started </dt><dd className="inline text-ink data-text">{formatDateTime(run.timing?.startedAt ?? null)}</dd></div><div><dt className="inline">Completed </dt><dd className="inline text-ink data-text">{formatDateTime(run.timing?.completedAt ?? null)}</dd></div><div><dt className="inline">Duration </dt><dd className="inline text-ink data-text">{formatDuration(run.timing?.durationMs ?? null)}</dd></div><div><dt className="inline">ATIF digest </dt><dd className="inline break-all text-ink data-text">{run.atifDigest}</dd></div><div><dt className="inline">Trajectory artifact </dt><dd className="inline break-all text-ink data-text">{run.atifArtifactId ?? "Unavailable"}</dd></div><div><dt className="inline">Usage </dt><dd className="inline text-ink">Unavailable</dd></div></dl>
    </article>
  );
}

function Runs({ model, taskId, selectedRunId }: { model: CloudTaskViewModel; taskId: string; selectedRunId: string | null }) {
  return (
    <section id="runs" aria-labelledby="runs-title" className="border-b border-line py-8 sm:py-10">
      <div className="flex items-baseline justify-between gap-4"><h2 id="runs-title" className="text-lg font-semibold text-ink">Runs</h2><span className="text-xs text-muted data-text">{model.runs.length}</span></div>
      <p className="mt-3 max-w-3xl text-sm leading-6 text-muted">Run state, timing, role, and content digests are the complete public run evidence. Private usage and raw event bytes are not part of this graph.</p>
      <div className="mt-5 border-t border-line">{model.runs.length ? model.runs.map((run) => <RunEvidence key={run.runId} taskId={taskId} run={run} selected={run.runId === selectedRunId} />) : <p className="py-6 text-sm text-muted">No runs are published for this task.</p>}</div>
    </section>
  );
}

function TrajectorySurface({ model, taskId }: { model: CloudTaskViewModel; taskId: string }) {
  const trajectory = model.trajectory;
  const descriptor = trajectory.descriptor;
  const action = trajectory.action;
  const artifact = model.artifacts.find((item) => item.artifactId === action?.artifactId) ?? null;
  const download = artifact ? artifactHref(taskId, artifact) : null;
  return (
    <section id="trajectory" aria-labelledby="trajectory-title" className="border-b border-line py-8 sm:py-10">
      <div className="flex flex-col gap-2 sm:flex-row sm:items-baseline sm:justify-between"><h2 id="trajectory-title" className="text-lg font-semibold text-ink">Complete trajectory</h2><Status value={trajectory.state === "available" ? "available" : "unavailable"} /></div>
      <p className="mt-3 max-w-3xl text-sm leading-6 text-muted">The immutable descriptor is the boundary for the complete trajectory. Rendering is deferred until the validated trajectory reader is active.</p>
      <div className="mt-5 border-y border-line bg-contrast-field px-5 py-5 text-contrast-ink">
        {descriptor ? <dl className="grid gap-x-6 gap-y-3 text-xs sm:grid-cols-2 lg:grid-cols-4"><div><dt className="text-contrast-muted">Run</dt><dd className="mt-1 break-all font-medium data-text">{descriptor.runId}</dd></div><div><dt className="text-contrast-muted">Pipeline</dt><dd className="mt-1 break-all font-medium data-text">{descriptor.pipelineId}</dd></div><div><dt className="text-contrast-muted">Role</dt><dd className="mt-1 font-medium">{titleCase(descriptor.role)}</dd></div><div><dt className="text-contrast-muted">Availability</dt><dd className="mt-1 font-medium">{titleCase(descriptor.availability)}</dd></div><div><dt className="text-contrast-muted">Artifact</dt><dd className="mt-1 break-all font-medium data-text">{descriptor.artifactId ?? "Unavailable"}</dd></div><div><dt className="text-contrast-muted">Size</dt><dd className="mt-1 font-medium data-text">{formatBytes(descriptor.byteSize)}</dd></div><div><dt className="text-contrast-muted">Digest</dt><dd className="mt-1 break-all font-medium data-text">{descriptor.sha256}</dd></div><div><dt className="text-contrast-muted">State</dt><dd className="mt-1 font-medium">{titleCase(descriptor.runState)}</dd></div></dl> : <p className="text-sm leading-6">{model.completeness.warnings[0] ?? "A complete trajectory descriptor is not available in this publication."}</p>}
        <p className="mt-5 border-t border-contrast-line pt-4 text-sm leading-6">{descriptor ? "Complete trajectory rendering is pending; the published descriptor is immutable." : "No trajectory bytes are exposed until a complete immutable descriptor is available."}</p>
        {download ? <a href={download} className="mt-4 inline-flex items-center gap-2 text-sm font-medium text-contrast-ink underline underline-offset-4"><FileDown aria-hidden="true" size={14} />Download trajectory artifact</a> : null}
      </div>
    </section>
  );
}

function Artifacts({ model, taskId, selectedRunId }: { model: CloudTaskViewModel; taskId: string; selectedRunId: string | null }) {
  return (
    <section id="artifacts" aria-labelledby="artifacts-title" className="border-b border-line py-8 sm:py-10">
      <div className="flex items-baseline justify-between gap-4"><h2 id="artifacts-title" className="text-lg font-semibold text-ink">Artifacts</h2><span className="text-xs text-muted data-text">{model.artifacts.length}</span></div>
      <p className="mt-3 max-w-3xl text-sm leading-6 text-muted">Artifacts are addressed by their validated logical path. Available objects use same-origin actions; unavailable objects remain unavailable.</p>
      <div className="mt-5 border-t border-line">{model.artifacts.length ? <ul>{model.artifacts.map((artifact) => { const href = artifactHref(taskId, artifact); const selected = selectedRunId === artifact.runId; return <li key={artifact.artifactId} className={`border-b border-line py-5 ${selected ? "border-l-2 border-l-accent pl-4" : ""}`}><div className="flex flex-col gap-2 sm:flex-row sm:items-baseline sm:justify-between"><span className="break-all text-sm font-semibold text-ink data-text">{artifact.artifactId}</span><Status value={artifact.availability} /></div><dl className="mt-3 grid gap-x-6 gap-y-2 text-xs text-muted sm:grid-cols-2 lg:grid-cols-4"><div><dt className="inline">Run </dt><dd className="inline break-all text-ink data-text">{artifact.runId}</dd></div><div><dt className="inline">Path </dt><dd className="inline break-all text-ink data-text">{artifact.logicalPath}</dd></div><div><dt className="inline">Media type </dt><dd className="inline break-all text-ink data-text">{artifact.mediaType}</dd></div><div><dt className="inline">Size </dt><dd className="inline text-ink data-text">{formatBytes(artifact.byteSize)}</dd></div></dl><p className="mt-2 text-xs text-muted">{artifact.disclosure.redactionApplied ? "Redacted public object" : "Unredacted public object"} · {artifact.disclosure.originalRetained ? "Original retained" : "Original unavailable"}</p>{href ? <a href={href} className="mt-3 inline-flex items-center gap-2 text-xs font-medium text-accent"><FileDown aria-hidden="true" size={14} />{artifact.action?.kind === "trajectory" ? "Download trajectory artifact" : "Download artifact"}</a> : <p className="mt-3 text-xs text-faint">Artifact unavailable</p>}</li>; })}</ul> : <p className="py-6 text-sm text-muted">No artifacts are published for this task.</p>}</div>
    </section>
  );
}

function TaskFooter() {
  return <footer className="border-t border-line"><div className="mx-auto flex max-w-shell flex-col gap-3 px-4 py-8 text-xs text-muted sm:flex-row sm:items-center sm:justify-between sm:px-8 lg:px-12"><p>Steward execution evidence. Missing values remain missing.</p><a href="https://github.com/minhuw/coquic" className="inline-flex items-center gap-1.5 text-inherit hover:text-ink">Source repository<ExternalLink aria-hidden="true" size={13} /></a></div></footer>;
}

interface PageProps {
  params: Promise<{ taskId: string }>;
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}

export default async function StewardTaskPage({ params, searchParams }: PageProps) {
  const [{ taskId }, query] = await Promise.all([params, searchParams]);
  let detail: CloudTaskDetail | null = null;
  let model: CloudTaskViewModel | null = null;
  let unavailable = false;
  try {
    detail = await getCloudRepository().getTaskDetail(taskId);
    if (detail) model = buildCloudTaskViewModel(detail);
  } catch {
    unavailable = true;
  }
  if (!unavailable && detail === null) notFound();

  const githubStars = await getGitHubStars();
  if (unavailable || !model) return <TaskUnavailable taskId={taskId} githubStars={githubStars} />;

  const requestedRunId = typeof query.run === "string" ? query.run : null;
  const requestedPipelineId = typeof query.pipeline === "string" ? query.pipeline : null;
  const requestedRun = requestedRunId ? model.runs.find((run) => run.runId === requestedRunId) ?? null : null;
  const selectedPipelineId = requestedPipelineId && model.pipelines.some((pipeline) => pipeline.pipelineId === requestedPipelineId)
    ? requestedPipelineId
    : requestedRun?.pipelineId ?? model.task.pipelineId ?? model.pipelines[0]?.pipelineId ?? null;
  const completedRun = model.task.completedRunId ? model.runs.find((run) => run.runId === model.task.completedRunId) ?? null : null;
  const selectedRunId = requestedRun?.runId
    ?? (completedRun?.pipelineId === selectedPipelineId ? completedRun.runId : null)
    ?? model.runs.find((run) => run.pipelineId === selectedPipelineId)?.runId
    ?? null;

  return <>
    <SiteHeader githubStars={githubStars} />
    <main id="content"><div className="mx-auto max-w-shell px-4 sm:px-8 lg:px-12">
      <TaskHeader model={model} />
      <Pipelines model={model} taskId={taskId} selectedPipelineId={selectedPipelineId} selectedRunId={selectedRunId} />
      <Runs model={model} taskId={taskId} selectedRunId={selectedRunId} />
      <TrajectorySurface model={model} taskId={taskId} />
      <Artifacts model={model} taskId={taskId} selectedRunId={selectedRunId} />
    </div></main>
    <TimelineDrawer events={Array.from(model.timeline)} completeness={{ state: model.completeness.state, warnings: Array.from(model.completeness.warnings) }} />
    <TaskFooter />
  </>;
}

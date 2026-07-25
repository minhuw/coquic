import type { Metadata } from "next";
import {
  ArrowLeft,
  ChevronDown,
  ExternalLink,
  Flag,
  GitCommitHorizontal,
  ShieldAlert,
} from "lucide-react";
import Link from "next/link";
import { notFound } from "next/navigation";
import { SiteHeader } from "@/components/site-header";
import { getGitHubStars } from "@/lib/github";
import { PatchViewer } from "./patch-viewer";
import { TimelineDrawer } from "./timeline-drawer";
import { AttemptDisclosure } from "./attempt-disclosure";
import { DurationStrip } from "./duration-strip";
import { PipelineGraph, type PipelineStage, type PipelineTransition } from "./pipeline-graph";
import { RunConfiguration } from "./run-configuration";
import { TranscriptLayout, type RunOutlinePhase, type RunPhaseKind } from "./transcript-layout";
import { LazyTranscript, type TranscriptRecord } from "./lazy-transcript";
import { getArchiveRepository } from "@/lib/steward-archive/repository";
import { loadArchiveTaskView, loadInitialTranscript } from "@/lib/steward-archive/view-model";
import { RevisionMonitor } from "../../revision-monitor";

export const metadata: Metadata = { title: "Steward task" };

type ArtifactView = "transcript" | "patch" | "validation" | "review";
const artifactViews: ArtifactView[] = ["transcript", "patch", "validation", "review"];

interface TaskData {
  task: {
    id: string; title: string; kind: string; workflow: string; worker: string;
    priority: string; risk: string; status: string; summary: string;
    createdAt: string; updatedAt: string; sourceSignalIds: string[];
    issueUrl?: string | null; plannerRunId: string; commit: string | null; commitUrl: string | null;
  };
  pipeline: {
    stages: PipelineStage[];
    transitions: PipelineTransition[];
  };
  plan: {
    objective: string; sourceContext: string; constraints: string[];
    validationCommands: string[]; completeness: string;
    steps?: Array<{ title: string; detail: string; files: string[] }>;
  };
  planRuns?: Array<{
    number: number; name: string; status: string; startedAt: string;
    completedAt: string | null; durationSeconds: number | null;
    model: string | null; reasoningEffort: string | null;
    eventCount: number; exitCode: number | null; summary: string;
    transcript: {
      availability: string; mode: string; sizeBytes: number;
      originalSizeBytes: number; truncated: boolean; text: string;
    };
    transcriptPath?: string | null;
  }>;
  attempts: Array<{
    number: number; pipelineId?: string; label: string; status: string; startedAt: string;
    completedAt: string | null; summary: string;
    workerRun: { name?: string; sessionId?: string; resumeOfRunId?: string | null; parentRunId?: string | null; retryOfRunId?: string | null; transcriptPath?: string | null; model?: string | null; reasoningEffort?: string | null; events: number; exitCode: number | null; status: string; initialCursor?: string | null; hasMore?: boolean; fileRevision?: string | null };
    reviewerRun: { name?: string; model?: string | null; reasoningEffort?: string | null; events: number; exitCode: number | null; status: string } | null;
    runs: Array<{ runId: string; role: string; roleOrdinal: number; state: string; sessionId: string; resumeOfRunId: string | null; parentRunId: string | null; retryOfRunId: string | null; startedAt: string; completedAt: string | null; model: string | null; reasoning: string | null; result: { status?: string; summary?: string | null }; usage: { availability?: string; promptTokens?: number | null; completionTokens?: number | null; totalTokens?: number | null }; cost: { availability?: string; estimatedMicroUsd?: number | null; currency?: string | null }; transcriptPath?: string | null; completeRecords: number; exitCode: number | null }>;
    integration: { state?: string; commit?: string | null; resultPath?: string | null; startedAt?: string; completedAt?: string | null };
    artifacts: { transcriptBytes: number; patchBytes: number; lastMessageBytes: number; transcriptTruncated: boolean };
  }>;
  transcript: TranscriptItem[];
  patches: Array<{
    attempt: number; pipelineId?: string; filesChanged: number; additions: number; deletions: number; rawUrl: string | null;
    files: Array<{
      path: string; status: string; additions: number; deletions: number;
      hunks: Array<{
        header: string;
        lines: Array<{ type: "context" | "addition" | "deletion"; oldLine: number | null; newLine: number | null; content: string }>;
      }>;
    }>;
  }>;
  validations: Array<{ id: string; pipelineId?: string; attempt: number; command: string; status: string; exitCode: number | null; durationSeconds: number; summary: string; summaryTruncated: boolean; outputUrl?: string }>;
  reviews: Array<{
    id?: string; pipelineId?: string; attempt: number; kind?: string; role?: string; verdict: string; summary: string;
    findings: Array<{ severity: string; title: string; file: string; line: number | null; detail: string; recommendation: string }>;
    validationGaps: string[]; remainingRisk: string;
  }>;
  timeline: Array<{ id: string; stage: string; kind: string; timestamp: string; title: string; detail: string }>;
  completeness: { state: string; transcript: string; warnings: string[] };
}

interface TranscriptItem {
  id: string; ordinal?: number; attempt: number; kind: string; label: string; timestamp?: string; text?: string;
  durationSeconds?: number; durationMs?: number; command?: string; output?: string; outputTruncated?: boolean; exitCode?: number | null;
  outputBytes?: number; changes?: Array<{ path: string; kind: string }>;
  todos?: Array<{ text: string; completed: boolean }>;
}

interface ArchiveTranscript {
  items: TranscriptItem[];
  usage: {
    turns: Array<{ ordinal: number; inputTokens: number; cachedInputTokens: number; outputTokens: number; reasoningOutputTokens: number }>;
    inputTokens: number;
    cachedInputTokens: number;
    uncachedInputTokens: number;
    outputTokens: number;
    reasoningOutputTokens: number;
    totalTokens: number;
  } | null;
  timing: null;
}

function titleCase(value: string) {
  return value.replace(/([A-Z])/g, " $1").replace(/[._-]/g, " ").replace(/^./, (letter) => letter.toUpperCase());
}

function taskKindTone(value: string) {
  if (value === "feature") return "bg-accent";
  if (value === "ci") return "bg-positive";
  return "bg-muted";
}

function formatDateTime(value: string) {
  return new Intl.DateTimeFormat("en-US", { month: "short", day: "numeric", hour: "numeric", minute: "2-digit", timeZone: "UTC", timeZoneName: "short" }).format(new Date(value));
}

function Status({ value }: { value: string }) {
  const tone = value === "running" || value === "active" ? "text-accent" : value === "complete" || value === "succeeded" || value === "pushed" || value === "passed" || value === "accepted" || value === "accept" ? "text-positive" : value === "blocked" || value === "block" || value === "failed" || value === "invalid" || value === "revision-requested" || value === "validation-failed" ? "text-negative" : "text-muted";
  return <span className={`font-medium ${tone}`}>{titleCase(value)}</span>;
}

function formatDurationSeconds(value: number | null) {
  if (value === null) return "In progress";
  if (value < 60) return `${value}s`;
  const minutes = Math.floor(value / 60);
  const seconds = value % 60;
  return seconds ? `${minutes}m ${seconds}s` : `${minutes}m`;
}

function formatArtifactBytes(value: number) {
  if (value >= 1_000_000) return `${(value / 1_000_000).toFixed(1).replace(/\.0$/, "")} MB`;
  if (value >= 1_000) return `${(value / 1_000).toFixed(value >= 100_000 ? 0 : 1).replace(/\.0$/, "")} KB`;
  return `${value} B`;
}

function issueReference(value: string) {
  try {
    const segments = new URL(value).pathname.split("/").filter(Boolean);
    const issueIndex = segments.lastIndexOf("issues");
    const issueNumber = issueIndex === -1 ? null : segments[issueIndex + 1];
    return issueNumber && /^\d+$/.test(issueNumber) ? `#${issueNumber}` : "Issue";
  } catch {
    return "Issue";
  }
}

function ImplementationPlan({ plan }: { plan: TaskData["plan"] }) {
  return (
    <section aria-labelledby="plan-title" className="border-b border-line py-8 sm:py-10">
      <div className="grid gap-7 lg:grid-cols-[minmax(0,1.45fr)_minmax(22rem,0.8fr)] lg:gap-12">
        <div>
          <div className="flex items-baseline gap-3"><h2 id="plan-title" className="text-lg font-semibold text-ink">Run brief</h2><span className="text-xs text-positive">{titleCase(plan.completeness)}</span></div>
          <p className="mt-4 max-w-3xl text-lg leading-7 text-ink">{plan.objective}</p>
          <p className="mt-3 max-w-3xl text-sm leading-6 text-muted [overflow-wrap:anywhere]">{plan.sourceContext}</p>
          {plan.steps?.length ? <ol className="mt-6 border-t border-line">{plan.steps.map((step, index) => <li key={step.title} className="border-b border-line"><details><summary className="grid cursor-pointer list-none grid-cols-[2rem_minmax(0,1fr)] gap-3 py-3 text-sm font-medium text-ink"><span className="text-xs text-muted data-text">{String(index + 1).padStart(2, "0")}</span><span>{step.title}</span></summary><div className="pb-4 pl-11"><p className="text-xs leading-5 text-muted">{step.detail}</p>{step.files.length ? <p className="mt-2 break-words text-xs leading-5 text-faint data-text">{step.files.join(" · ")}</p> : null}</div></details></li>)}</ol> : null}
        </div>
        <dl className="border-t border-line">
          <div className="border-b border-line py-4">
            <dt className="flex items-baseline justify-between gap-4 text-xs font-medium text-muted"><span>Constraints</span><span className="data-text">{plan.constraints.length}</span></dt>
            <dd className="mt-3">
              <ul className="space-y-2 text-sm leading-6 text-ink">
                {plan.constraints.map((constraint) => <li key={constraint} className="relative pl-4 before:absolute before:left-0 before:top-[0.7rem] before:size-1 before:bg-faint">{constraint}</li>)}
              </ul>
            </dd>
          </div>
          <div className="border-b border-line py-3"><dt className="text-xs font-medium text-muted">Required checks · <span className="data-text">{plan.validationCommands.length}</span></dt><dd className="mt-2 space-y-1 text-xs leading-5 text-ink data-text">{plan.validationCommands.map((item) => <span key={item} className="block break-words">{item}</span>)}</dd></div>
        </dl>
      </div>
    </section>
  );
}

function PlanningRuns({ runs, taskId, privateTranscripts }: { runs: NonNullable<TaskData["planRuns"]>; taskId: string; privateTranscripts: Map<number, ArchiveTranscript> }) {
  return (
    <section id="planning-runs" aria-labelledby="planning-runs-title" className="border-b border-line pt-8 sm:pt-10">
      <div className="flex items-baseline justify-between gap-4">
        <h2 id="planning-runs-title" className="text-lg font-semibold text-ink">Planning runs</h2>
        <span className="text-xs text-muted data-text">{runs.length}</span>
      </div>
      <div className="mt-5 border-t border-line">
        {runs.map((run) => {
          const privateTranscript = privateTranscripts.get(run.number) ?? null;
          const transcriptItems: TranscriptItem[] = privateTranscript
            ? privateTranscript.items.map((item) => ({ ...item, attempt: run.number }))
            : run.transcript.availability === "available" && run.transcript.text
              ? [{ id: `plan-${run.number}-transcript`, attempt: run.number, kind: "reasoning", label: "Published planner transcript tail", timestamp: run.startedAt, text: run.transcript.text }]
              : [];
          const anchorPrefix = `plan-run-${run.number + 1}`;
          return (
            <details id={anchorPrefix} key={run.name} className="group scroll-mt-20 border-b-2 border-line-strong last:border-b-0">
              <summary className="grid cursor-pointer list-none gap-3 px-3 py-4 sm:grid-cols-[6rem_minmax(0,1fr)_8rem_14rem] sm:items-start sm:gap-5">
                <span className="text-xs text-muted data-text">Run {String(run.number + 1).padStart(2, "0")}</span>
                <span className="min-w-0">
                  <span className="block break-all text-sm font-semibold text-ink data-text">{run.name}</span>
                  <span className="mt-1 block max-w-3xl text-sm leading-6 text-muted">{run.summary}</span>
                </span>
                <span className="text-sm"><Status value={run.status} /></span>
                <span className="flex self-stretch items-start justify-end gap-3 text-xs text-muted data-text">
                  <span className="flex min-h-full min-w-0 flex-col items-end justify-between gap-2 text-right"><span>{formatDurationSeconds(run.durationSeconds)}</span><RunConfiguration model={run.model} reasoningEffort={run.reasoningEffort} /></span>
                  <ChevronDown aria-hidden="true" size={16} className="mt-0.5 shrink-0 transition-transform duration-fast group-open:rotate-180" />
                </span>
              </summary>
              <div className="pb-8 pt-4">
                {!privateTranscript && run.transcript.truncated ? <p className="mt-5 text-xs text-warning">Published planner transcript tail · {formatArtifactBytes(run.transcript.sizeBytes)} of {formatArtifactBytes(run.transcript.originalSizeBytes)}</p> : null}
                <div className="mt-5">
                  {transcriptItems.length || run.transcriptPath ? <TranscriptPanel items={transcriptItems} anchorPrefix={anchorPrefix} taskId={taskId} truncated={!privateTranscript && run.transcript.truncated} privateTranscript={privateTranscript} transcriptRunId={run.name} transcriptPath={run.transcriptPath} initialHasMore={Boolean(run.transcriptPath)} privateScope="plan" privateIndex={run.number} unavailableTarget="run" showCadence={false} /> : <EmptyEvidence title="Planner transcript not published" detail="This planning run has metadata, but no transcript content is available in this publication." />}
                </div>
              </div>
            </details>
          );
        })}
      </div>
    </section>
  );
}

function AttemptsEvidence({ data, selectedAttempt, selectedRunId, taskId, artifact, selectedFile, privateTranscript }: { data: TaskData; selectedAttempt: number; selectedRunId: string | null; taskId: string; artifact: ArtifactView; selectedFile?: string; privateTranscript: ArchiveTranscript | null }) {
  return (
    <section id="attempts" aria-labelledby="attempt-title" className="scroll-mt-20 border-b border-line py-8 sm:py-10">
      <div className="flex items-baseline justify-between gap-4"><h2 id="attempt-title" className="text-lg font-semibold text-ink">Processing pipelines</h2><span className="text-xs text-muted data-text">{data.attempts.length}</span></div>
      <div className="mt-5 border-t border-line">
        {data.attempts.map((item) => {
          const current = item.number === selectedAttempt;
          const eventCount = item.runs.reduce((total, run) => total + run.completeRecords, 0);
          const hasPublishedTranscript = data.transcript.some((event) => event.attempt === item.number);
          const privateActive = current && artifact === "transcript" && privateTranscript !== null;
          const showPublicationWarnings = !privateActive && (data.task.status === "running" || artifact === "transcript" && hasPublishedTranscript);
          const itemRunId = current ? selectedRunId : item.workerRun.name ?? null;
          const evidenceHref = (view: ArtifactView) => `/steward/tasks/${encodeURIComponent(taskId)}?attempt=${item.number}${itemRunId ? `&run=${encodeURIComponent(itemRunId)}` : ""}&artifact=${view}#attempt-${item.number + 1}-evidence`;
          return (
            <AttemptDisclosure key={item.number} id={`attempt-${item.number + 1}-evidence`} current={current} number={item.number} label={item.label} summary={item.summary} status={<Status value={item.status} />} eventCount={eventCount} model={item.workerRun.model} reasoningEffort={item.workerRun.reasoningEffort}>
                <section aria-label={`${item.label} owned runs`} className="mb-7 border-y border-line">
                  <div className="flex items-baseline justify-between gap-4 py-3"><h3 className="text-sm font-semibold text-ink">Owned runs</h3><span className="text-xs text-muted data-text">{item.runs.length}</span></div>
                  <ol className="border-t border-line">{item.runs.map((run) => { const selected = current && run.runId === selectedRunId; return <li key={run.runId} className={`grid gap-3 border-b border-line py-4 last:border-b-0 lg:grid-cols-[minmax(12rem,1fr)_minmax(14rem,1fr)_minmax(12rem,0.8fr)] ${selected ? "border-l-2 border-l-accent pl-3" : ""}`}>
                    <div className="min-w-0"><p className="break-all text-sm font-semibold text-ink data-text">{run.runId}</p><p className="mt-1 text-xs text-muted">{titleCase(run.role)} run {run.roleOrdinal} · <Status value={run.state} /></p><p className="mt-2 text-xs leading-5 text-muted">{run.result?.summary ?? "No run result summary available."}</p>{run.transcriptPath ? <Link href={`/steward/tasks/${encodeURIComponent(taskId)}?attempt=${item.number}&run=${encodeURIComponent(run.runId)}&artifact=transcript#attempt-${item.number + 1}-evidence`} aria-current={selected ? "page" : undefined} aria-label={`View transcript for ${run.runId}`} className="mt-3 inline-block text-xs font-medium text-accent">{selected ? "Selected transcript" : "View transcript"}</Link> : <p className="mt-3 text-xs text-faint">Transcript unavailable</p>}</div>
                    <dl className="text-xs text-muted"><div className="flex justify-between gap-3 py-1"><dt>Session</dt><dd className="break-all text-right text-ink data-text">{run.sessionId}</dd></div>{run.resumeOfRunId ? <div className="flex justify-between gap-3 py-1"><dt>Resumes</dt><dd className="break-all text-right text-ink data-text">{run.resumeOfRunId}</dd></div> : null}{run.parentRunId ? <div className="flex justify-between gap-3 py-1"><dt>Parent</dt><dd className="break-all text-right text-ink data-text">{run.parentRunId}</dd></div> : null}{run.retryOfRunId ? <div className="flex justify-between gap-3 py-1"><dt>Retries</dt><dd className="break-all text-right text-ink data-text">{run.retryOfRunId}</dd></div> : null}<div className="flex justify-between gap-3 py-1"><dt>Records</dt><dd className="text-ink data-text">{run.completeRecords}</dd></div></dl>
                    <dl className="text-xs text-muted"><div className="flex justify-between gap-3 py-1"><dt>Model</dt><dd className="text-right text-ink data-text">{run.model ?? "Unavailable"}</dd></div><div className="flex justify-between gap-3 py-1"><dt>Reasoning</dt><dd className="text-right text-ink">{run.reasoning ?? "Unavailable"}</dd></div><div className="flex justify-between gap-3 py-1"><dt>Tokens</dt><dd className="text-right text-ink data-text">{run.usage.totalTokens == null ? titleCase(run.usage.availability ?? "unavailable") : run.usage.totalTokens.toLocaleString("en-US")}</dd></div><div className="flex justify-between gap-3 py-1"><dt>Cost</dt><dd className="text-right text-ink data-text">{run.cost.estimatedMicroUsd == null ? titleCase(run.cost.availability ?? "unavailable") : `$${(run.cost.estimatedMicroUsd / 1_000_000).toFixed(6)}`}</dd></div></dl>
                  </li>; })}</ol>
                  <dl className="grid border-t border-line py-3 text-xs text-muted sm:grid-cols-3"><div><dt>Integration</dt><dd className="mt-1 text-ink"><Status value={item.integration?.state ?? "unavailable"} /></dd></div><div><dt>Commit</dt><dd className="mt-1 break-all text-ink data-text">{item.integration?.commit ?? "Unavailable"}</dd></div><div><dt>Result evidence</dt><dd className="mt-1 break-all text-ink data-text">{item.integration?.resultPath ?? "Unavailable"}</dd></div></dl>
                </section>
                {showPublicationWarnings && data.completeness.warnings.length ? <div className="mb-5 border-y border-line py-3 text-xs leading-5"><p className="font-medium text-warning">{titleCase(data.completeness.state)} publication</p><ul className="mt-1 text-muted">{data.completeness.warnings.map((warning) => <li key={warning}>{warning}</li>)}</ul></div> : null}
                {!privateActive && artifact === "transcript" && hasPublishedTranscript ? <p className="mb-4 max-w-3xl text-xs leading-5 text-warning">{data.completeness.transcript}</p> : null}
                <nav aria-label={`Pipeline ${item.number + 1} evidence`} className="flex max-w-full overflow-x-auto border-b border-line">{artifactViews.map((view) => <Link key={view} href={evidenceHref(view)} aria-current={artifact === view ? "page" : undefined} className={`shrink-0 border-b-2 px-4 py-3 text-sm font-medium no-underline first:pl-0 ${artifact === view ? "border-accent text-accent" : "border-transparent text-muted"}`}>{titleCase(view)}</Link>)}</nav>
                <div className="pt-6"><ArtifactPanel view={artifact} data={data} attempt={item.number} taskId={taskId} transcriptTruncated={item.artifacts.transcriptTruncated} selectedFile={current ? selectedFile : undefined} privateTranscript={privateActive ? privateTranscript : null} /></div>
            </AttemptDisclosure>
          );
        })}
      </div>
    </section>
  );
}

function commandPhase(command: string, afterChange: boolean): RunPhaseKind {
  const value = command.toLowerCase();
  if (/\b(pre-commit|zig build test|npm (run )?test|pnpm (run )?test|pytest|cargo test|gtest_filter|ctest|typecheck|lint\b)/.test(value)) return "validate";
  if (/\bgit (diff|status)\b/.test(value) && afterChange) return "review";
  if (/\b(apply_patch|perl -[pi]|sed -i)\b/.test(value)) return "implement";
  return "inspect";
}

function commandActivity(command: string, phase: RunPhaseKind) {
  const value = command.replace(/^\/bin\/bash\s+-lc\s+/, "").trim();
  const lower = value.toLowerCase();
  if (/\bpre-commit\b/.test(lower)) return "Run repository checks";
  if (/\bgtest_filter\b/.test(lower)) return "Run focused tests";
  if (/\bzig build test\b/.test(lower)) return "Run full test suite";
  if (/\bzig build\b/.test(lower)) return "Build project";
  if (/\bgit diff --check\b/.test(lower)) return "Check patch hygiene";
  if (/\bgit diff\b/.test(lower)) return "Review code changes";
  if (/\bgit status\b/.test(lower)) return "Check worktree state";
  if (/\bgh issue view\b/.test(lower)) return "Inspect source issue";
  if (/rag\/scripts\/query-rag/.test(lower)) return "Query QUIC references";
  if (/\b(?:rg|grep)\b/.test(lower)) return "Search repository";
  if (/\b(?:sed -n|cat|head|tail|nl -ba)\b/.test(lower)) return "Read source and guidance";
  if (phase === "implement") return "Apply source changes";
  return "Run repository command";
}

function buildRunOutline(items: TranscriptItem[]): RunOutlinePhase[] {
  const phaseOrder: RunPhaseKind[] = ["understand", "inspect", "implement", "validate", "review"];
  const labels: Record<RunPhaseKind, string> = {
    understand: "Understand & plan",
    inspect: "Inspect",
    implement: "Implement",
    validate: "Validate",
    review: "Final review",
  };
  const phases = new Map<RunPhaseKind, RunOutlinePhase>(phaseOrder.map((kind) => [kind, { kind, label: labels[kind], summary: "", events: [] }]));
  const firstChange = items.findIndex((item) => item.kind === "file");

  items.forEach((item, index) => {
    const afterChange = firstChange !== -1 && index > firstChange;
    let phase: RunPhaseKind;
    let label: string;
    if (item.kind === "tool") {
      phase = commandPhase(item.command ?? "", afterChange);
      label = commandActivity(item.command ?? "", phase);
    } else if (item.kind === "file") {
      phase = "implement";
      const files = item.changes?.length ?? 0;
      label = `${files} ${files === 1 ? "file" : "files"} changed`;
    } else if (item.kind === "todo") {
      phase = afterChange ? "implement" : "understand";
      const complete = item.todos?.filter((todo) => todo.completed).length ?? 0;
      label = `Plan ${complete}/${item.todos?.length ?? 0} complete`;
    } else {
      phase = afterChange ? "implement" : "understand";
      label = item.label || "Agent reasoning";
    }
    const outcome = item.kind !== "tool" || item.exitCode === undefined ? null : item.exitCode === null ? "running" : item.exitCode === 0 ? "passed" : "failed";
    phases.get(phase)!.events.push({ id: item.id, sequence: index + 1, label, outcome });
  });

  return phaseOrder.flatMap((kind) => {
    const phase = phases.get(kind)!;
    if (!phase.events.length) return [];
    const failed = phase.events.filter((event) => event.outcome === "failed").length;
    const running = phase.events.filter((event) => event.outcome === "running").length;
    if (kind === "implement") {
      const files = new Set(items.filter((item) => item.kind === "file").flatMap((item) => item.changes?.map((change) => change.path) ?? [])).size;
      phase.summary = `${files} ${files === 1 ? "file" : "files"} · ${phase.events.length} events`;
    } else if (kind === "validate") {
      const passed = phase.events.filter((event) => event.outcome === "passed").length;
      phase.summary = running ? `${passed} passed · ${running} running` : `${passed}/${phase.events.length} passed`;
    } else {
      phase.summary = `${phase.events.length} ${phase.events.length === 1 ? "event" : "events"}${failed ? ` · ${failed} failed` : ""}${running ? ` · ${running} running` : ""}`;
    }
    return [phase];
  });
}

function compactTokenCount(value: number) {
  if (value >= 1_000_000) return `${(value / 1_000_000).toFixed(value >= 10_000_000 ? 1 : 2).replace(/\.0+$/, "")}M`;
  if (value >= 1_000) return `${(value / 1_000).toFixed(value >= 100_000 ? 0 : 1).replace(/\.0$/, "")}K`;
  return value.toLocaleString("en-US");
}

function ModelUsage({ id, usage, eventCount, commandCount, privateTranscript, truncated, unavailableTarget }: { id: string; usage: ArchiveTranscript["usage"]; eventCount: number; commandCount: number; privateTranscript: boolean; truncated: boolean; unavailableTarget: "attempt" | "run" }) {
  const activity = <p className={`text-muted data-text sm:ml-auto ${truncated ? "text-warning" : ""}`}>{usage ? <>{usage.turns.length} {usage.turns.length === 1 ? "turn" : "turns"} · </> : null}{eventCount} events · {commandCount} {privateTranscript ? "commands" : "tool calls"}{truncated ? " · Published excerpt" : null}</p>;
  if (!usage) {
    return (
      <section aria-labelledby={id} className="border-b border-line py-3">
        <div className="flex flex-wrap items-baseline gap-x-5 gap-y-1 text-xs">
          <h3 id={id} className="font-semibold text-ink">Model usage</h3>
          <p className="text-muted">Not recorded for this {unavailableTarget}</p>
          {activity}
        </div>
      </section>
    );
  }

  const metrics = [
    { label: "Total", value: usage.totalTokens },
    { label: "Input", value: usage.inputTokens },
    { label: "Cached", value: usage.cachedInputTokens },
    { label: "Output", value: usage.outputTokens },
    { label: "Reasoning", value: usage.reasoningOutputTokens },
  ];

  return (
    <section aria-labelledby={id} className="border-b border-line py-3">
      <div className="flex flex-wrap items-baseline gap-x-5 gap-y-2 text-xs">
        <h3 id={id} className="font-semibold text-ink">Model usage</h3>
        <dl className="flex flex-wrap items-baseline gap-x-5 gap-y-2">
          {metrics.map((metric) => (
            <div key={metric.label} className="flex items-baseline gap-1.5">
              <dt className="text-faint">{metric.label}</dt>
              <dd className="font-semibold text-ink data-text" title={metric.value.toLocaleString("en-US")}>{compactTokenCount(metric.value)}</dd>
            </div>
          ))}
        </dl>
        {activity}
      </div>
      {usage.turns.length > 1 ? (
        <details className="border-t border-line text-xs">
          <summary className="cursor-pointer py-3 font-medium text-ink">Turn breakdown</summary>
          <ol className="border-t border-line">
            {usage.turns.map((turn) => (
              <li key={turn.ordinal} className="grid gap-1 border-b border-line py-3 text-muted data-text sm:grid-cols-[5rem_repeat(4,minmax(0,1fr))]">
                <span className="font-medium text-ink">Turn {turn.ordinal}</span>
                <span>{turn.inputTokens.toLocaleString("en-US")} input</span>
                <span>{turn.cachedInputTokens.toLocaleString("en-US")} cached</span>
                <span>{turn.outputTokens.toLocaleString("en-US")} output</span>
                <span>{turn.reasoningOutputTokens.toLocaleString("en-US")} reasoning</span>
              </li>
            ))}
          </ol>
        </details>
      ) : null}
    </section>
  );
}

function TranscriptPanel({ items, anchorPrefix, taskId, truncated, privateTranscript, transcriptRunId, transcriptPath, initialCursor, initialHasMore, fileRevision, privateScope = "attempt", privateIndex = 0, privateTranscriptName, unavailableTarget = "attempt", showCadence = true }: { items: TranscriptItem[]; anchorPrefix: string; taskId: string; truncated: boolean; privateTranscript: ArchiveTranscript | null; transcriptRunId?: string; transcriptPath?: string | null; initialCursor?: string | null; initialHasMore?: boolean; fileRevision?: string | null; privateScope?: "attempt" | "plan"; privateIndex?: number; privateTranscriptName?: string; unavailableTarget?: "attempt" | "run"; showCadence?: boolean }) {
  const toolCalls = items.filter((item) => item.kind === "tool").length;
  return (
    <div aria-label="Agent transcript">
      {privateTranscript && showCadence ? <DurationStrip anchorPrefix={anchorPrefix} transcript={privateTranscript} /> : null}
      <ModelUsage id={`${anchorPrefix}-model-usage-title`} usage={privateTranscript?.usage ?? null} eventCount={items.length} commandCount={toolCalls} privateTranscript={privateTranscript !== null} truncated={truncated} unavailableTarget={unavailableTarget} />
      <TranscriptLayout anchorPrefix={anchorPrefix} phases={buildRunOutline(items)}>
        <LazyTranscript taskId={taskId} runId={privateTranscript ? undefined : transcriptRunId} path={privateTranscript ? undefined : transcriptPath} initialCursor={initialCursor} initialHasMore={initialHasMore} fileRevision={fileRevision} initial={items.map((item): TranscriptRecord => ({ ordinal: item.ordinal ?? Number(item.id.split("-").at(-1) ?? 0), timestamp: item.timestamp ?? null, value: item.text ?? item.command ?? item.label, id: item.id, kind: titleCase(item.kind), label: item.label, text: item.text, command: item.command, output: item.output, exitCode: item.exitCode }))} />
      </TranscriptLayout>
    </div>
  );
}

function ArtifactPanel({ view, data, attempt, taskId, transcriptTruncated, selectedFile, privateTranscript }: { view: ArtifactView; data: TaskData; attempt: number; taskId: string; transcriptTruncated: boolean; selectedFile?: string; privateTranscript: ArchiveTranscript | null }) {
  const attemptData = data.attempts.find((item) => item.number === attempt)!;
  if (view === "transcript") {
    const items: TranscriptItem[] = privateTranscript
      ? privateTranscript.items.map((item) => ({ ...item, attempt }))
      : data.transcript.filter((item) => item.attempt === attempt);
    if (!items.length && !attemptData.workerRun.transcriptPath) return <EmptyEvidence title="Transcript not available" detail="This run has no declared transcript artifact." />;
    return <TranscriptPanel items={items} anchorPrefix={`attempt-${attempt + 1}`} taskId={taskId} truncated={privateTranscript ? false : transcriptTruncated} privateTranscript={privateTranscript} transcriptRunId={attemptData.workerRun.name} transcriptPath={attemptData.workerRun.transcriptPath} initialCursor={attemptData.workerRun.initialCursor} initialHasMore={attemptData.workerRun.hasMore} fileRevision={attemptData.workerRun.fileRevision} privateIndex={attempt} privateTranscriptName={attemptData.workerRun.name} />;
  }
  if (view === "patch") {
    const patch = data.patches.find((item) => item.attempt === attempt) ?? data.patches.find((item) => item.pipelineId === attemptData.pipelineId);
    if (!patch) return <EmptyEvidence title="Structured patch not published" detail={attemptData.artifacts.patchBytes ? "Patch metadata exists for this attempt, but no file-level diff was included in this publication." : "No patch artifact exists for this attempt at this snapshot."} />;
    if (!patch.files.length) return <div className="border-y border-line py-8"><p className="font-medium text-ink">Raw patch evidence</p><p className="mt-2 text-sm text-muted">The canonical patch remains attached to this pipeline and loads only on request.</p>{patch.rawUrl ? <a className="mt-4 inline-block text-sm text-accent" href={patch.rawUrl}>Download raw patch</a> : null}</div>;
    return <PatchViewer patch={patch} initialPath={selectedFile} />;
  }
  if (view === "validation") {
    const records = data.validations.filter((record) => record.attempt === attempt || record.pipelineId === attemptData.pipelineId);
    if (!records.length) return <EmptyEvidence title="Validation not started" detail="No validation records exist for the selected attempt at this snapshot." />;
    return <ul className="border-t border-line">{records.map((record) => <li key={record.id} className="grid gap-4 border-b border-line py-5 sm:grid-cols-[8rem_minmax(0,1fr)_7rem]"><div><Status value={record.status} /><p className="mt-1 text-xs text-muted data-text">exit {record.exitCode ?? "unavailable"}</p></div><div><p className="break-words text-sm font-medium text-ink data-text">{record.command}</p>{record.summaryTruncated ? <p className="mt-2 text-xs text-warning">Earlier output omitted · published tail</p> : null}<pre aria-label={record.summaryTruncated ? "Published validation tail" : undefined} className="mt-2 max-h-40 overflow-auto whitespace-pre-wrap text-xs leading-5 text-muted data-text">{record.summary}</pre>{record.outputUrl ? <a href={record.outputUrl} className="mt-3 inline-block text-xs font-medium text-accent">Download validation log</a> : null}</div><p className="text-xs text-muted data-text sm:text-right">{record.durationSeconds}s</p></li>)}</ul>;
  }
  const reviewRecords = data.reviews.filter((record) => record.attempt === attempt || record.pipelineId === attemptData.pipelineId);
  if (!reviewRecords.length) return <EmptyEvidence title="Review not started" detail="No reviewer record exists for the selected run's pipeline at this snapshot." />;
  return <div>{reviewRecords.map((review) => <section key={review.id ?? `${review.kind}-${review.role}`} className="border-b border-line pb-8 last:border-b-0"><div className="flex items-baseline justify-between gap-4 border-y border-line py-4"><h3 className="text-base font-semibold text-ink">{review.kind ? titleCase(review.kind) : "Reviewer"} evidence · {review.role ?? "reviewer"}</h3><Status value={review.verdict} /></div><p className="mt-5 text-sm leading-7 text-muted">{review.summary}</p>{review.findings.map((finding) => <article key={finding.title} className="mt-7 border-l-2 border-negative pl-5"><p className="text-xs font-medium text-negative">{titleCase(finding.severity)} finding</p><h4 className="mt-2 font-semibold text-ink">{finding.title}</h4><p className="mt-2 break-all text-xs text-muted data-text">{finding.file}{finding.line ? `:${finding.line}` : ""}</p><p className="mt-3 text-sm leading-7 text-muted">{finding.detail}</p><p className="mt-3 text-sm leading-7 text-ink"><strong className="font-medium">Required change:</strong> {finding.recommendation}</p></article>)}<p className="mt-7 text-sm leading-6 text-muted"><strong className="font-medium text-ink">Remaining risk:</strong> {review.remainingRisk}</p></section>)}</div>;
}

function EmptyEvidence({ title, detail }: { title: string; detail: string }) {
  return <div className="border-y border-line py-8"><p className="font-medium text-ink">{title}</p><p className="mt-2 text-sm leading-6 text-muted">{detail}</p></div>;
}

interface PageProps {
  params: Promise<{ taskId: string }>;
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}

export default async function StewardTaskPage({ params, searchParams }: PageProps) {
  const [{ taskId }, query] = await Promise.all([params, searchParams]);
  const repository = getArchiveRepository();
  const initialRevision = repository.getRevision().revision;
  const archiveData = await loadArchiveTaskView(repository, taskId);
  const data = archiveData as TaskData | null;
  if (!data) notFound();
  const provenance = repository.getTaskProvenance(taskId);
  const requestedView = typeof query.artifact === "string" ? query.artifact : "transcript";
  const artifact: ArtifactView = artifactViews.includes(requestedView as ArtifactView) ? requestedView as ArtifactView : "transcript";
  const requestedAttempt = typeof query.attempt === "string" ? Number(query.attempt) : data.attempts.at(-1)?.number ?? 0;
  const attempt = data.attempts.some((item) => item.number === requestedAttempt) ? requestedAttempt : data.attempts.at(-1)?.number ?? 0;
  const selectedFile = typeof query.file === "string" ? query.file : undefined;
  const selectedAttempt = data.attempts.find((item) => item.number === attempt)!;
  const requestedRun = typeof query.run === "string" ? query.run : null;
  const selectedRun = requestedRun ? selectedAttempt.runs.find((run) => run.runId === requestedRun && run.transcriptPath) : selectedAttempt.runs.find((run) => run.runId === selectedAttempt.workerRun.name);
  const selectedRunId = selectedRun?.runId ?? selectedAttempt.workerRun.name ?? null;
  if (selectedRun) selectedAttempt.workerRun = { name: selectedRun.runId, sessionId: selectedRun.sessionId, resumeOfRunId: selectedRun.resumeOfRunId, parentRunId: selectedRun.parentRunId, retryOfRunId: selectedRun.retryOfRunId, transcriptPath: selectedRun.transcriptPath, model: selectedRun.model, reasoningEffort: selectedRun.reasoning, events: selectedRun.completeRecords, exitCode: selectedRun.exitCode, status: selectedRun.state, initialCursor: null, hasMore: false };
  if (artifact === "transcript" && selectedAttempt?.workerRun.name && selectedAttempt.workerRun.transcriptPath) {
    try {
      const initial = await loadInitialTranscript(repository, taskId, selectedAttempt.workerRun.name, selectedAttempt.workerRun.transcriptPath, attempt);
      data.transcript.push(...initial.items);
      selectedAttempt.workerRun.initialCursor = initial.nextCursor;
      selectedAttempt.workerRun.hasMore = initial.hasMore;
      selectedAttempt.workerRun.fileRevision = initial.fileRevision;
    } catch { /* an active replacement is reported by the evidence panel without exposing bytes */ }
  }
  const privateTranscript: ArchiveTranscript | null = null;
  const privatePlanTranscripts = new Map<number, ArchiveTranscript>();
  const githubStars = await getGitHubStars();

  return <>
    <SiteHeader githubStars={githubStars} />
    <RevisionMonitor initialRevision={initialRevision} />
    <main id="content"><div className="mx-auto max-w-shell px-4 sm:px-8 lg:px-12">
      <header className="py-10 sm:py-12">
        <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <Link href="/steward?view=tasks" className="inline-flex items-center gap-2 text-sm font-medium text-muted no-underline hover:text-ink"><ArrowLeft aria-hidden="true" size={15} />All tasks</Link>
          <span className="break-all text-xs text-faint data-text sm:text-right">{data.task.id}</span>
        </div>
        <div className="mt-7 grid gap-7 lg:grid-cols-[minmax(0,1fr)_16rem] lg:items-start">
          <div className="min-w-0"><div className="flex flex-wrap items-center gap-x-3 gap-y-2 text-sm"><Status value={data.task.status} /><span className="inline-flex items-center gap-2 font-medium text-ink"><span aria-hidden="true" className={`h-4 w-1.5 ${taskKindTone(data.task.kind)}`} />{titleCase(data.task.kind)}</span><span className="text-muted [overflow-wrap:anywhere]">{data.task.worker}</span></div><h1 className="mt-3 max-w-4xl text-3xl font-medium leading-tight text-ink [overflow-wrap:anywhere] sm:text-4xl">{data.task.title}</h1></div>
          <dl className="border-t border-line text-xs"><div className="flex justify-between gap-4 border-b border-line py-3"><dt className="inline-flex items-center gap-1.5 text-muted"><Flag aria-hidden="true" size={12} />Priority</dt><dd className="text-ink">{titleCase(data.task.priority)}</dd></div><div className="flex justify-between gap-4 border-b border-line py-3"><dt className="inline-flex items-center gap-1.5 text-muted"><ShieldAlert aria-hidden="true" size={12} />Risk</dt><dd className="text-ink">{titleCase(data.task.risk)}</dd></div><div className="flex justify-between gap-4 border-b border-line py-3"><dt className="text-muted">Updated</dt><dd className="text-right data-text">{formatDateTime(data.task.updatedAt)}</dd></div>{data.task.issueUrl ? <div className="flex justify-between gap-4 border-b border-line py-3"><dt className="text-muted">Issue</dt><dd><a href={data.task.issueUrl} target="_blank" rel="noreferrer" aria-label={`Open GitHub issue ${issueReference(data.task.issueUrl)}`} title={`Open GitHub issue ${issueReference(data.task.issueUrl)}`} className="inline-flex items-center gap-1.5 text-accent no-underline"><span aria-hidden="true">{issueReference(data.task.issueUrl)}</span><ExternalLink aria-hidden="true" size={12} /></a></dd></div> : null}{data.task.commit && data.task.commitUrl ? <div className="flex justify-between gap-4 border-b border-line py-3"><dt className="text-muted">Commit</dt><dd><a href={data.task.commitUrl} className="inline-flex items-center gap-1.5 text-accent"><GitCommitHorizontal aria-hidden="true" size={13} />{data.task.commit.slice(0, 10)}</a></dd></div> : null}</dl>
        </div>
      </header>

      {provenance ? <section aria-label="Control-loop provenance" className="border-y border-line py-5"><p className="text-xs font-medium text-muted">Control-loop provenance</p><div className="mt-3 flex flex-wrap gap-x-4 gap-y-2 text-xs">{provenance.proposals.map((proposal) => <Link key={proposal.proposalId} href={`/steward?view=planning&run=${encodeURIComponent(proposal.plannerRunId)}&proposal=${encodeURIComponent(proposal.proposalId)}`} className="text-accent">{proposal.plannerRunId} · {proposal.outcome}</Link>)}{provenance.signals.map((signalId) => <Link key={signalId} href={`/steward?view=signals&signal=${encodeURIComponent(signalId)}`} className="text-accent">Signal {signalId}</Link>)}</div></section> : null}
      <PipelineGraph stages={data.pipeline.stages} transitions={data.pipeline.transitions} />
      <ImplementationPlan plan={data.plan} />
      {data.planRuns?.length ? <PlanningRuns runs={data.planRuns} taskId={taskId} privateTranscripts={privatePlanTranscripts} /> : null}
      <AttemptsEvidence data={data} selectedAttempt={attempt} selectedRunId={selectedRunId} taskId={taskId} artifact={artifact} selectedFile={selectedFile} privateTranscript={privateTranscript} />
    </div></main>
    <TimelineDrawer events={data.timeline} completeness={data.completeness} />
    <footer className="border-t border-line"><div className="mx-auto flex max-w-shell flex-col gap-3 px-4 py-8 text-xs text-muted sm:flex-row sm:items-center sm:justify-between sm:px-8 lg:px-12"><p>Steward execution evidence. Missing artifacts remain missing.</p><a href="https://github.com/minhuw/coquic" className="inline-flex items-center gap-1.5 text-inherit hover:text-ink">Source repository<ExternalLink aria-hidden="true" size={13} /></a></div></footer>
  </>;
}

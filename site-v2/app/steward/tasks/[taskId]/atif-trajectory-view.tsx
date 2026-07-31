import {
  AlertCircle,
  CheckCircle2,
  ChevronRight,
  CircleHelp,
  Clock3,
  FileText,
  GitBranch,
  Wrench,
  XCircle,
} from "lucide-react";
import type { ReactNode } from "react";
import type {
  AtifArtifactAction,
  AtifDisplayContentValue,
  AtifDisplayLineageReference,
  AtifDisplayMetrics,
  AtifDisplayModel,
  AtifDisplayObservation,
  AtifDisplayStep,
  AtifDisplayToolCall,
  AtifSafeRecord,
  AtifSafeValue,
} from "@/lib/steward-archive/atif-view-model";
import { RunConfiguration } from "./run-configuration";
import { TranscriptLayout, type RunOutlinePhase } from "./transcript-layout";
import { TranscriptMessage } from "./transcript-message";

interface AtifTrajectoryViewProps {
  model: AtifDisplayModel;
  /** The caller may provide a route-stable prefix for deep links. */
  anchorPrefix?: string;
}

function hasOwn(value: object | null | undefined, key: string): boolean {
  return Boolean(value) && Object.prototype.hasOwnProperty.call(value, key);
}

function asDisplayText(value: unknown, present = true): string {
  if (!present || value === null || value === undefined) return "Unavailable";
  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") return String(value);
  return JSON.stringify(value);
}

function formatTimestamp(value: string | null | undefined): ReactNode {
  if (!value) return <span className="text-unavailable">Unavailable</span>;
  return <time dateTime={value} className="data-text">{value}</time>;
}

function formatDuration(value: number | null | undefined): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return "Unavailable";
  if (value < 1_000) return `${value} ms`;
  const seconds = value / 1_000;
  return `${seconds.toFixed(seconds % 1 === 0 ? 0 : 1)} s`;
}

function formatBytes(value: number): string {
  if (!Number.isFinite(value) || value < 0) return "Unavailable";
  if (value >= 1_000_000) return `${(value / 1_000_000).toFixed(1).replace(/\.0$/, "")} MB`;
  if (value >= 1_000) return `${(value / 1_000).toFixed(value >= 100_000 ? 0 : 1).replace(/\.0$/, "")} KB`;
  return `${value} B`;
}

function labelForRole(role: AtifDisplayStep["source"]): string {
  return role.charAt(0).toUpperCase() + role.slice(1);
}

function normalizeAnchor(value: string): string {
  const normalized = value.replace(/[^A-Za-z0-9_.-]+/g, "-").replace(/^-+|-+$/g, "");
  return normalized || "trajectory";
}

function fieldRows(rows: readonly [string, ReactNode][]) {
  return (
    <dl className="border-y border-line text-xs">
      {rows.map(([label, value], index) => (
        <div key={label} className={`flex min-w-0 justify-between gap-4 py-3 ${index < rows.length - 1 ? "border-b border-line" : ""}`}>
          <dt className="shrink-0 text-muted">{label}</dt>
          <dd className="min-w-0 break-words text-right text-ink data-text">{value}</dd>
        </div>
      ))}
    </dl>
  );
}

function DisclosureSummary({ model }: { model: AtifDisplayModel }) {
  return (
    <p className="mt-4 flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-muted">
      <span>{model.disclosure.redactionApplied ? "Public values redacted" : "Public values unchanged"}</span>
      <span aria-hidden="true" className="text-faint">·</span>
      <span>{model.disclosure.originalRetained ? "Original retained" : "Original unavailable"}</span>
    </p>
  );
}

function RunSummary({ model, anchorPrefix }: { model: AtifDisplayModel; anchorPrefix: string }) {
  const configuredStep = model.steps.find((step) => step.modelName || step.reasoningEffort !== undefined);
  const metadata = model.metadata;
  return (
    <header aria-labelledby={`${anchorPrefix}-title`} className="border-b border-line pb-6">
      <div className="flex flex-wrap items-center justify-between gap-3 text-xs text-muted">
        <span className="inline-flex items-center gap-1.5 font-medium text-positive"><CheckCircle2 aria-hidden="true" size={14} />Completed run</span>
        <span className="break-all data-text">{model.runId || "Run unavailable"}</span>
      </div>
      <h2 id={`${anchorPrefix}-title`} className="mt-3 text-2xl font-medium leading-tight text-ink sm:text-3xl">Complete trajectory</h2>
      <p className="mt-2 max-w-3xl text-sm leading-6 text-muted">Every validated record is shown in source order. Missing evidence remains unavailable.</p>
      <DisclosureSummary model={model} />
      <div className="mt-6 grid gap-6 lg:grid-cols-[minmax(0,1fr)_22rem] lg:items-start">
        <div className="min-w-0">
          <p className="mb-3 text-xs font-semibold uppercase tracking-[0.08em] text-muted">Run facts</p>
          {fieldRows([
            ["Task", model.taskId || "Unavailable"],
            ["Pipeline", model.pipelineId || "Unavailable"],
            ["Role", model.role || "Unavailable"],
            ["Schema", model.schemaVersion || "Unavailable"],
            ["Started", formatTimestamp(metadata.timing.startedAt)],
            ["Completed", formatTimestamp(metadata.timing.completedAt)],
            ["Duration", `${formatDuration(metadata.timing.durationMs)}${metadata.timing.durationSource === "derived" ? " (derived)" : ""}`],
          ])}
        </div>
        <div className="min-w-0 border-t border-line pt-3 lg:border-t-0 lg:pt-0">
          <p className="mb-3 text-xs font-semibold uppercase tracking-[0.08em] text-muted">Agent configuration</p>
          {fieldRows([
            ["Agent", model.agent.name || "Unavailable"],
            ["Version", model.agent.version || "Unavailable"],
            ["Model", model.agent.modelName || "Unavailable"],
          ])}
          {configuredStep ? <div className="mt-3"><RunConfiguration model={configuredStep.modelName} reasoningEffort={configuredStep.reasoningEffort} /></div> : null}
        </div>
      </div>
    </header>
  );
}

function safeRecordEntries(record: AtifSafeRecord | null | undefined): readonly [string, AtifSafeValue][] {
  return record ? Object.entries(record) as readonly [string, AtifSafeValue][] : [];
}

function SafeRecordBlock({ record, label }: { record: AtifSafeRecord | null | undefined; label: string }) {
  const entries = safeRecordEntries(record);
  if (entries.length === 0) return null;
  return (
    <details className="mt-4 border-t border-line pt-3">
      <summary className="group flex cursor-pointer list-none items-center gap-2 text-xs font-medium text-muted"><ChevronRight aria-hidden="true" size={14} className="transition-transform duration-fast group-open:rotate-90" />{label}</summary>
      <pre className="mt-3 max-w-full overflow-auto bg-diff-gutter px-3 py-3 text-xs leading-5 text-ink data-text">{JSON.stringify(Object.fromEntries(entries), null, 2)}</pre>
    </details>
  );
}

function MetricRows({ metrics, titleId }: { metrics: AtifDisplayMetrics | null | undefined; titleId: string }) {
  if (metrics === undefined) return null;
  const rows: readonly [string, string][] = [
    ["Cached tokens", asDisplayText(metrics?.cachedTokens, hasOwn(metrics, "cachedTokens"))],
    ["Prompt tokens", asDisplayText(metrics?.promptTokens, hasOwn(metrics, "promptTokens"))],
    ["Completion tokens", asDisplayText(metrics?.completionTokens, hasOwn(metrics, "completionTokens"))],
    ["Cost (USD)", asDisplayText(metrics?.costUsd, hasOwn(metrics, "costUsd"))],
    ["Prompt token IDs", asDisplayText(metrics?.promptTokenIds, hasOwn(metrics, "promptTokenIds"))],
    ["Completion token IDs", asDisplayText(metrics?.completionTokenIds, hasOwn(metrics, "completionTokenIds"))],
    ["Logprobs", asDisplayText(metrics?.logprobs, hasOwn(metrics, "logprobs"))],
  ];
  return (
    <section aria-labelledby={titleId} className="mt-5 border-t border-line pt-4">
      <h4 id={titleId} className="text-xs font-semibold uppercase tracking-[0.08em] text-muted">Metrics</h4>
      {fieldRows(rows)}
      <SafeRecordBlock record={metrics?.extensions} label="Metric extensions" />
    </section>
  );
}

function FinalMetrics({ model }: { model: AtifDisplayModel }) {
  const metrics = model.finalMetrics;
  if (metrics === undefined) return null;
  const rows: readonly [string, string][] = [
    ["Total steps", asDisplayText(metrics?.totalSteps, hasOwn(metrics, "totalSteps"))],
    ["Prompt tokens", asDisplayText(metrics?.totalPromptTokens, hasOwn(metrics, "totalPromptTokens"))],
    ["Completion tokens", asDisplayText(metrics?.totalCompletionTokens, hasOwn(metrics, "totalCompletionTokens"))],
    ["Cached tokens", asDisplayText(metrics?.totalCachedTokens, hasOwn(metrics, "totalCachedTokens"))],
    ["Cost (USD)", asDisplayText(metrics?.totalCostUsd, hasOwn(metrics, "totalCostUsd"))],
  ];
  return (
    <section aria-labelledby="trajectory-metrics-title" className="mt-8 border-t border-line pt-6">
      <h3 id="trajectory-metrics-title" className="text-sm font-semibold text-ink">Final metrics</h3>
      <div className="mt-3">{fieldRows(rows)}</div>
      <SafeRecordBlock record={metrics?.extensions} label="Final metric extensions" />
    </section>
  );
}

function statusFromCall(call: AtifDisplayToolCall): { label: string; failed: boolean; running: boolean; duration: string } {
  const extensions = call.extensions;
  const rawStatus = extensions && (extensions.status ?? extensions.state ?? extensions.outcome);
  const status = typeof rawStatus === "string" ? rawStatus.toLowerCase() : undefined;
  const failed = status === "failed" || status === "error" || status === "cancelled" || status === "canceled" || extensions?.ok === false || extensions?.failed === true || typeof extensions?.error === "string";
  const running = status === "running" || status === "in_progress" || status === "pending";
  const rawDuration = extensions?.durationMs ?? extensions?.duration;
  const duration = typeof rawDuration === "number" ? formatDuration(rawDuration) : asDisplayText(rawDuration, rawDuration !== undefined);
  return { label: failed ? "Failed" : running ? "Running" : status ? status : "Unavailable", failed, running, duration };
}

function Observation({ observation, index }: { observation: AtifDisplayObservation; index: number }) {
  const paired = observation.matchedCallId !== null;
  const content: AtifDisplayContentValue = observation.content;
  const parts = observation.parts.length > 0 ? observation.parts : undefined;
  return (
    <li className="border-t border-line py-4" data-observation data-paired={paired ? "true" : "false"}>
      <div className="flex flex-wrap items-center justify-between gap-2 text-xs">
        <span className={paired ? "text-muted" : "font-medium text-warning"}>{paired ? "Paired observation" : "Unpaired observation"}</span>
        <span className="data-text text-faint">{observation.sourceCallId ?? `observation-${index + 1}`}</span>
      </div>
      <TranscriptMessage content={content} parts={parts} />
      {observation.lineage ? <LineageReferences references={observation.lineage} label="Observation lineage" /> : null}
      <SafeRecordBlock record={observation.extensions} label="Observation extensions" />
    </li>
  );
}

function ToolCall({ call }: { call: AtifDisplayToolCall }) {
  const state = statusFromCall(call);
  return (
    <details data-tool-call={call.callId} data-tool-status={state.label.toLowerCase()} open={state.failed} className="border-t border-line py-3">
      <summary className="grid cursor-pointer list-none gap-2 sm:grid-cols-[minmax(0,1fr)_auto] sm:items-start">
        <span className="flex min-w-0 items-start gap-2"><Wrench aria-hidden="true" size={14} className="mt-0.5 shrink-0 text-accent" /><span className="min-w-0"><span className="block break-words text-sm font-medium text-ink">{call.functionName || "Unnamed tool"}</span><span className="mt-1 block break-all text-xs text-muted data-text">{call.callId}</span></span></span>
        <span className={`flex items-center gap-1.5 text-xs data-text ${state.failed ? "text-negative" : state.running ? "text-accent" : "text-muted"}`}>{state.failed ? <XCircle aria-hidden="true" size={13} /> : state.running ? <Clock3 aria-hidden="true" size={13} /> : <CircleHelp aria-hidden="true" size={13} />}{state.label}<span className="text-faint">· {state.duration}</span></span>
      </summary>
      <div className="mt-3 min-w-0 space-y-4">
        <div>
          <h5 className="text-xs font-semibold uppercase tracking-[0.08em] text-muted">Arguments</h5>
          <pre className="mt-2 max-w-full overflow-auto bg-diff-gutter px-3 py-3 text-xs leading-5 text-ink data-text">{JSON.stringify(call.arguments, null, 2)}</pre>
        </div>
        {call.observations.length > 0 ? <div><h5 className="text-xs font-semibold uppercase tracking-[0.08em] text-muted">Results</h5><ol className="mt-1">{call.observations.map((observation, index) => <Observation key={`${call.callId}-observation-${index}`} observation={observation} index={index} />)}</ol></div> : <p className="text-sm text-unavailable">No observation recorded.</p>}
        <SafeRecordBlock record={call.extensions} label="Tool extensions" />
      </div>
    </details>
  );
}

function LineageReferences({ references, label = "Lineage references" }: { references: readonly AtifDisplayLineageReference[]; label?: string }) {
  return (
    <section className="mt-4 border-t border-line pt-3" aria-label={label}>
      <h5 className="flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.08em] text-muted"><GitBranch aria-hidden="true" size={13} />{label}</h5>
      {references.length === 0 ? <p className="mt-2 text-sm text-unavailable">None recorded.</p> : <ul className="mt-2 space-y-2">{references.map((reference, index) => <li key={`${reference.trajectoryId ?? "trajectory"}-${reference.sessionId ?? "session"}-${index}`} className="grid min-w-0 gap-1 border-l-2 border-line pl-3 text-xs sm:grid-cols-[8rem_minmax(0,1fr)]"><span className="text-muted">Trajectory</span><span className="break-all text-ink data-text">{reference.trajectoryId ?? "Unavailable"}</span><span className="text-muted">Session</span><span className="break-all text-ink data-text">{reference.sessionId ?? "Unavailable"}</span><SafeRecordBlock record={reference.extensions} label="Reference extensions" /></li>)}</ul>}
    </section>
  );
}

function StepRecord({ step, eventId }: { step: AtifDisplayStep; eventId: string }) {
  const observations = step.observations.filter((observation) => observation.matchedCallId === null);
  const configured = step.modelName || step.reasoningEffort !== undefined;
  return (
    <li id={eventId} data-trajectory-anchor={step.anchor} className="scroll-mt-24 border-b border-line-strong py-8 first:pt-0" data-step-source={step.source}>
      <article aria-labelledby={`${eventId}-title`}>
        <header className="grid min-w-0 gap-3 sm:grid-cols-[minmax(0,1fr)_auto] sm:items-start">
          <div className="min-w-0">
            <p className="text-xs font-semibold uppercase tracking-[0.08em] text-muted">Record {String(step.stepId).padStart(2, "0")} · {labelForRole(step.source)}</p>
            <h3 id={`${eventId}-title`} className="mt-2 break-words text-xl font-medium text-ink">{labelForRole(step.source)} message</h3>
          </div>
          <div className="flex min-w-0 flex-col items-end gap-2 text-right text-xs text-muted data-text">
            {formatTimestamp(step.timestamp)}
            {configured ? <RunConfiguration model={step.modelName} reasoningEffort={step.reasoningEffort} /> : null}
          </div>
        </header>

        <TranscriptMessage content={step.message} parts={step.parts.length > 0 ? step.parts : undefined} />

        {step.reasoning !== undefined && step.reasoning !== null ? <details data-reasoning className="mt-6 max-w-3xl border-y border-line py-3"><summary className="cursor-pointer list-none text-sm font-medium text-muted">Reasoning</summary><div className="mt-3 text-sm leading-6 text-muted [overflow-wrap:anywhere]"><TranscriptMessage text={step.reasoning} /></div></details> : null}
        <MetricRows metrics={step.metrics} titleId={`${eventId}-metrics`} />

        {step.calls.length > 0 ? <section aria-labelledby={`${eventId}-tools`} className="mt-6 max-w-4xl border-t border-line"><h4 id={`${eventId}-tools`} className="flex items-center gap-2 py-3 text-sm font-semibold text-ink"><Wrench aria-hidden="true" size={15} />Tool calls <span className="text-xs font-normal text-muted data-text">{step.calls.length}</span></h4>{step.calls.map((call) => <ToolCall key={call.anchor} call={call} />)}</section> : null}

        {observations.length > 0 ? <section aria-labelledby={`${eventId}-observations`} className="mt-6 max-w-4xl border-t border-line"><h4 id={`${eventId}-observations`} className="flex items-center gap-2 py-3 text-sm font-semibold text-ink"><AlertCircle aria-hidden="true" size={15} />Unpaired observations <span className="text-xs font-normal text-muted data-text">{observations.length}</span></h4><ol>{observations.map((observation, index) => <Observation key={`${eventId}-unpaired-${index}`} observation={observation} index={index} />)}</ol></section> : null}
        {step.copiedContext !== undefined && step.copiedContext !== null ? <p className="mt-5 text-xs text-muted">{step.copiedContext ? "Copied context" : "Original context"}</p> : null}
        {step.llmCallCount !== undefined ? <p className="mt-2 text-xs text-muted data-text">LLM calls: {asDisplayText(step.llmCallCount)}</p> : null}
        <SafeRecordBlock record={step.extensions} label="Record extensions" />
      </article>
    </li>
  );
}

function ArtifactEntry({ artifact }: { artifact: AtifDisplayModel["artifacts"][number] }) {
  const action: AtifArtifactAction = artifact.action;
  return (
    <li className="grid min-w-0 gap-3 border-b border-line py-4 sm:grid-cols-[minmax(0,1fr)_minmax(0,18rem)] sm:items-start">
      <div className="min-w-0">
        <h4 className="break-all text-sm font-medium text-ink">{artifact.artifactId}</h4>
        <p className="mt-1 break-words text-xs text-muted">{artifact.mediaType} · {formatBytes(artifact.byteSize)} · owner record {artifact.ownerStepId}</p>
        <p className="mt-1 break-all text-xs text-faint data-text">SHA-256 {artifact.sha256}</p>
      </div>
      <div className="min-w-0 sm:text-right"><ArtifactAction action={action} /></div>
    </li>
  );
}

function ArtifactAction({ action }: { action: AtifArtifactAction }) {
  if (action.kind === "unavailable") return <span data-artifact-unavailable className="text-xs text-unavailable">Unavailable ({action.reason})</span>;
  return <a href={action.href} download className="inline-flex items-center gap-1 text-sm text-accent no-underline hover:text-ink"><FileText aria-hidden="true" size={14} />Download artifact</a>;
}

function LineageSummary({ model, titleId }: { model: AtifDisplayModel; titleId: string }) {
  const references = model.lineage.references;
  const children = model.lineage.trajectories;
  return (
    <section aria-labelledby={titleId} className="mt-8 border-t border-line pt-6">
      <h3 id={titleId} className="flex items-center gap-2 text-sm font-semibold text-ink"><GitBranch aria-hidden="true" size={15} />Lineage</h3>
      <div className="mt-3">{fieldRows([
        ["Trajectory", model.trajectoryId ?? model.lineage.trajectoryId ?? "Unavailable"],
        ["Session", model.sessionId ?? model.lineage.sessionId ?? "Unavailable"],
        ["References", references.length === 0 ? "None recorded" : String(references.length)],
        ["Child trajectories", children.length === 0 ? "None recorded" : String(children.length)],
      ])}</div>
      {references.length > 0 ? <LineageReferences references={references} /> : null}
      {children.length > 0 ? <ul className="mt-4 space-y-2">{children.map((child, index) => <li key={`${child.trajectoryId ?? "child"}-${index}`} className="border-l-2 border-line pl-3 text-xs"><span className="text-muted">Child trajectory</span><span className="ml-2 break-all text-ink data-text">{child.trajectoryId ?? "Unavailable"}</span><span className="ml-2 text-muted">{child.steps.length} records</span></li>)}</ul> : null}
    </section>
  );
}

function outlineFor(model: AtifDisplayModel, anchorPrefix: string): RunOutlinePhase[] {
  return [{
    kind: "understand",
    label: "Trajectory records",
    summary: `${model.steps.length} ${model.steps.length === 1 ? "record" : "records"}`,
    events: model.steps.map((step) => {
      const eventId = `${anchorPrefix}-event-${step.anchor}`;
      const states = step.calls.map((call) => statusFromCall(call));
      const outcome = states.some((state) => state.failed) ? "failed" : states.some((state) => state.running) ? "running" : states.length > 0 ? "passed" : null;
      return { id: step.anchor, anchor: eventId, sequence: step.stepId, label: `${labelForRole(step.source)} message`, outcome };
    }),
  }];
}

export function AtifTrajectoryView({ model, anchorPrefix: suppliedPrefix }: AtifTrajectoryViewProps) {
  const anchorPrefix = normalizeAnchor(suppliedPrefix ?? `trajectory-${model.taskId || model.runId || "run"}`);
  const phases = outlineFor(model, anchorPrefix);
  return (
    <section id={`${anchorPrefix}-trajectory`} aria-labelledby={`${anchorPrefix}-title`} data-atif-trajectory className="min-w-0">
      <RunSummary model={model} anchorPrefix={anchorPrefix} />
      <TranscriptLayout anchorPrefix={anchorPrefix} phases={phases}>
        {model.steps.length === 0 ? (
          <div data-empty-run className="border-y border-line py-10 text-center">
            <CheckCircle2 aria-hidden="true" size={22} className="mx-auto text-positive" />
            <h3 className="mt-3 text-lg font-medium text-ink">Completed empty run</h3>
            <p className="mt-2 text-sm text-muted">No trajectory records were published.</p>
          </div>
        ) : (
          <ol aria-label="Complete trajectory" data-trajectory-records className="min-w-0">
            {model.steps.map((step) => <StepRecord key={step.anchor} step={step} eventId={`${anchorPrefix}-event-${step.anchor}`} />)}
          </ol>
        )}
        <FinalMetrics model={model} />
        <LineageSummary model={model} titleId={`${anchorPrefix}-lineage-title`} />
        {model.artifacts.length > 0 ? <section aria-labelledby={`${anchorPrefix}-artifacts-title`} className="mt-8 border-t border-line pt-6"><h3 id={`${anchorPrefix}-artifacts-title`} className="flex items-center gap-2 text-sm font-semibold text-ink"><FileText aria-hidden="true" size={15} />Artifacts <span className="text-xs font-normal text-muted data-text">{model.artifacts.length}</span></h3><ul className="mt-3">{model.artifacts.map((artifact) => <ArtifactEntry key={artifact.artifactId} artifact={artifact} />)}</ul></section> : null}
      </TranscriptLayout>
    </section>
  );
}

export type { AtifTrajectoryViewProps };
export default AtifTrajectoryView;

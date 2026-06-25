"use client";

import Link from "next/link";
import {
  Background,
  Handle,
  MarkerType,
  Position,
  ReactFlow,
  type Edge,
  type Node,
  type NodeProps,
  type SmoothStepPathOptions,
} from "@xyflow/react";
import {
  Activity,
  CheckCircle2,
  ChevronRight,
  Circle,
  ExternalLink,
  FileText,
  GitBranch,
  ListChecks,
  RefreshCw,
  XCircle,
} from "lucide-react";
import { type ReactNode, useCallback, useEffect, useState } from "react";
import {
  getIterationPatch,
  getRunTranscriptWindow,
  getTask,
  getValidationLog,
  runTask,
} from "./api";
import { CodeBlock } from "./code-block";
import { TimelineEvent } from "./timeline";
import { TranscriptView } from "./transcript";
import type { CodexRunDiagnostics, EventRecord, TaskAttempt, TaskDetail, TaskRecord, TaskRunArtifact, TaskStatus, TranscriptWindow } from "./types";

type ReviewFinding = {
  severity: string;
  title: string;
  file: string;
  line: number | null;
  detail: string;
  recommendation: string;
};
type ReviewRecord = {
  attempt: number;
  created_at: string;
  event_kind: string;
  verdict: string;
  summary: string;
  findings: ReviewFinding[];
  validation_gaps: string[];
  remaining_risk: string;
  exit_code: number | null;
  command: string;
};
type TaskStageKey = "code" | "validation" | "review" | "integration";
type TaskStageState = "pending" | "active" | "complete" | "blocked";
type TaskStage = {
  key: TaskStageKey;
  label: string;
  state: TaskStageState;
  detail: string;
};
type AttemptTab = "transcript" | "patch" | "validation" | "review";
type TaskFlow = {
  stages: TaskStage[];
  active: ActiveStageInfo;
  loops: {
    validation: number;
    review: number;
    integration: number;
  };
};
type ActiveStageInfo = {
  key: TaskStageKey;
  attempt: TaskAttempt | null;
  live: boolean;
  tab: "transcript" | "validation" | "review" | "patch";
};

type LoadedTask = {
  detail: TaskDetail;
  iterationPatches: Record<number, string>;
  runTranscripts: Record<string, TranscriptWindow>;
};

export function TaskDetailRoute({ taskId }: { taskId: string }) {
  const [loaded, setLoaded] = useState<LoadedTask | null>(null);
  const [loadError, setLoadError] = useState("");
  const [validationLog, setValidationLog] = useState<{ index: number; text: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const [streamState, setStreamState] = useState("connecting");

  const loadTask = useCallback(async () => {
    const nextDetail = await getTask(taskId);
    const attempts = nextDetail.attempts ?? [];
    const runNames = Array.from(
      new Set(
        attempts.flatMap((attempt) => [
          attempt.worker?.name,
          attempt.reviewer?.name,
        ]).filter((name): name is string => Boolean(name)),
      ),
    );
    const patchAttempts = attempts.filter((attempt) => Boolean(attempt.patch_path));
    const [iterationPatchEntries, runEntries] = await Promise.all([
      Promise.all(
        patchAttempts.map(async (attempt) => [attempt.attempt, await getIterationPatch(taskId, attempt.attempt)] as const),
      ),
      Promise.all(
        runNames.map(async (name) => [name, await getRunTranscriptWindow(taskId, name)] as const),
      ),
    ]);
    setLoaded((current) => ({
      detail: nextDetail,
      iterationPatches: Object.fromEntries(iterationPatchEntries),
      runTranscripts: mergeTranscriptMaps(
        current?.runTranscripts ?? {},
        Object.fromEntries(runEntries),
      ),
    }));
    setLoadError("");
  }, [taskId]);

  const refreshTask = useCallback(async () => {
    try {
      await loadTask();
    } catch (error) {
      setLoadError(errorMessage(error, "Unable to load task detail."));
      setStreamState("reconnecting");
    }
  }, [loadTask]);

  useEffect(() => {
    const timer = window.setTimeout(() => void refreshTask(), 0);
    return () => window.clearTimeout(timer);
  }, [refreshTask]);

  useEffect(() => {
    const source = new EventSource("/api/stream");
    source.addEventListener("open", () => setStreamState("live"));
    source.addEventListener("error", () => setStreamState("reconnecting"));
    source.addEventListener("state", () => void refreshTask());
    return () => source.close();
  }, [refreshTask]);

  async function handleRunTask() {
    setBusy(true);
    try {
      await runTask(taskId);
      await refreshTask();
    } catch (error) {
      setLoadError(errorMessage(error, "Unable to run task."));
    } finally {
      setBusy(false);
    }
  }

  async function showValidation(index: number) {
    try {
      setValidationLog({ index, text: await getValidationLog(taskId, index) });
    } catch (error) {
      setLoadError(errorMessage(error, "Unable to load validation log."));
    }
  }

  async function loadEarlierTranscript(runName: string) {
    const current = loaded?.runTranscripts[runName];
    if (!loaded || !current || !current.has_before || current.start <= 0) return;
    try {
      const previous = await getRunTranscriptWindow(taskId, runName, {
        offset: Math.max(0, current.start - transcriptWindowLimit(current)),
      });
      setLoaded({
        ...loaded,
        runTranscripts: {
          ...loaded.runTranscripts,
          [runName]: mergeTranscriptWindows(previous, current),
        },
      });
    } catch (error) {
      setLoadError(errorMessage(error, "Unable to load earlier transcript."));
    }
  }

  if (!loaded) {
    return (
      <main className="task-page-frame">
        <section className="task-page-shell">
          <div className="empty-state">
            {loadError || "Loading task detail."}
            {loadError && (
              <button className="button-inline" onClick={() => void refreshTask()} type="button">
                Retry
              </button>
            )}
          </div>
        </section>
      </main>
    );
  }

  const task = loaded.detail.task;
  const events = loaded.detail.events ?? [];
  const attempts = loaded.detail.attempts ?? [];
  const reviews = reviewRecords(events);
  const flow = taskFlow(task, attempts, events);
  const timelineEvents = events.slice().reverse();

  return (
    <main className="task-page-frame">
      <section className="task-page-shell">
        <header className="task-page-topbar">
          <Link className="task-back-link" href="/">Back to dashboard</Link>
          <div className="top-actions">
            <span className={`stream-pill ${streamState}`}>{streamState}</span>
            <button className="icon-button secondary" onClick={() => void refreshTask()} type="button" title="Refresh task">
              <RefreshCw size={16} />
            </button>
            {task.status === "queued" && (
              <button disabled={busy} onClick={handleRunTask} type="button">Run Task</button>
            )}
          </div>
        </header>

        <TaskOverviewFacts detail={loaded.detail} task={task} />
        {loadError && <div className="inline-alert">{loadError}</div>}

        <div className="task-detail-layout">
          <main className="task-detail-main">
            <TaskFlowPanel flow={flow} />
            <AttemptStack
              activeStage={flow.active}
              attempts={attempts}
              iterationPatches={loaded.iterationPatches}
              onShowValidation={showValidation}
              onLoadEarlierTranscript={loadEarlierTranscript}
              reviews={reviews}
              runTranscripts={loaded.runTranscripts}
              task={task}
              validationLog={validationLog?.text || ""}
              validationLogIndex={validationLog?.index ?? null}
            />
          </main>
          <aside className="task-detail-aside">
            <section className="panel task-timeline-panel">
              <PanelTitle icon={<ListChecks size={17} />} title="Timeline" />
              <ol className="timeline compact">
                {timelineEvents.map((event) => <TimelineEvent event={event} key={`${event.created_at}-${event.kind}`} />)}
                {!events.length && <li className="muted">No events recorded.</li>}
              </ol>
            </section>
          </aside>
        </div>
      </section>
    </main>
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

function errorMessage(error: unknown, fallback: string) {
  if (error instanceof Error && error.message) return error.message;
  if (typeof error === "string" && error.trim()) return error;
  return fallback;
}

function TaskOverviewFacts({ detail, task }: { detail: TaskDetail | null; task: TaskRecord }) {
  const display = taskDisplay(task);
  const remote = detail?.remote;
  return (
    <section className="panel task-overview-card" aria-label="Task overview">
      <PanelTitle icon={<Activity size={17} />} title="Overview" />
      <div className="task-overview-head">
        <div className="task-title-row">
          <h1>{display.title}</h1>
          <StatusPill status={task.status} />
        </div>
        <p>{task.summary || "No task summary has been recorded yet."}</p>
        <div className="task-overview-meta" aria-label="Task facts">
          <FactPill label="Task" mono value={task.spec.id} />
          <FactPill label="Type" value={display.kind} />
          <FactPill label={isIntegrationTask(task) ? "Source" : "Agent"} value={display.worker} />
          <FactPill label="Updated" mono value={shortDate(task.updated_at)} />
          {remote?.commit && remote.commit_url && <GithubCommitLink commit={remote.commit} url={remote.commit_url} />}
        </div>
      </div>
    </section>
  );
}

function FactPill({ label, mono, value }: { label: string; mono?: boolean; value: string }) {
  return (
    <span className="fact-pill">
      <b>{label}</b>
      <span className={mono ? "mono" : ""}>{value}</span>
    </span>
  );
}

function TaskFlowPanel({ flow }: { flow: TaskFlow }) {
  const graph = pipelineGraph(flow);
  return (
    <section className="panel task-flow-panel" aria-label="Task iteration flow">
      <PanelTitle icon={<RouteIcon />} title="Current Iteration" />
      <div className="pipeline-graph" aria-label="Task pipeline graph">
        <ReactFlow
          defaultViewport={{ x: 34, y: 18, zoom: 1 }}
          edges={graph.edges}
          edgesFocusable={false}
          elementsSelectable={false}
          fitView={false}
          maxZoom={1}
          minZoom={1}
          nodeTypes={pipelineNodeTypes}
          nodes={graph.nodes}
          nodesConnectable={false}
          nodesDraggable={false}
          nodesFocusable={false}
          panOnDrag={false}
          panOnScroll={false}
          preventScrolling={false}
          proOptions={{ hideAttribution: true }}
          style={{ width: "760px", height: "206px" }}
          zoomOnDoubleClick={false}
          zoomOnPinch={false}
          zoomOnScroll={false}
        >
          <Background color="#e0e0e0" gap={18} size={1} />
        </ReactFlow>
      </div>
    </section>
  );
}

type PipelineNodeData = {
  stage?: TaskStage;
};
type PipelineNode = Node<PipelineNodeData, "pipeline">;
type PipelineEdge = Edge<Record<string, never>, "smoothstep"> & {
  pathOptions?: SmoothStepPathOptions;
};

const PIPELINE_NODE_WIDTH = 150;
const PIPELINE_NODE_HEIGHT = 76;
const PIPELINE_BOUND_SIZE = 1;

const pipelineNodeTypes = {
  pipeline: PipelineNodeCard,
};

function PipelineNodeCard({ data }: NodeProps<PipelineNode>) {
  if (!data.stage) {
    return <span className="pipeline-fit-bound" aria-hidden="true" />;
  }
  const stage = data.stage;
  return (
    <article className={`pipeline-node ${stage.state}`}>
      <Handle className="pipeline-node-handle" id="left" position={Position.Left} type="target" />
      <Handle className="pipeline-node-handle" id="right" position={Position.Right} type="source" />
      <Handle className="pipeline-node-handle" id="top-source" position={Position.Top} type="source" />
      <Handle className="pipeline-node-handle" id="top-target" position={Position.Top} type="target" />
      <Handle className="pipeline-node-handle" id="bottom-source" position={Position.Bottom} type="source" />
      <Handle className="pipeline-node-handle" id="bottom-target" position={Position.Bottom} type="target" />
      <div className="pipeline-node-head">
        <span className="pipeline-node-dot">{stage.state === "active" ? <Spinner /> : stageIcon(stage.state)}</span>
        <b>{stage.label}</b>
      </div>
      <p>{stage.detail}</p>
    </article>
  );
}

type FeedbackEdgeKind = "validation" | "review" | "integration";

function pipelineGraph(flow: TaskFlow): { nodes: PipelineNode[]; edges: PipelineEdge[] } {
  const fitBoundIds = ["fit-top-left", "fit-top-right", "fit-bottom-left", "fit-bottom-right"];
  const positions: Record<TaskStageKey, { x: number; y: number }> = {
    code: { x: 0, y: 52 },
    validation: { x: 178, y: 52 },
    review: { x: 356, y: 52 },
    integration: { x: 534, y: 52 },
  };
  const stages = Object.fromEntries(flow.stages.map((stage) => [stage.key, stage])) as Record<TaskStageKey, TaskStage>;
  const nodes: PipelineNode[] = [
    ...fitBoundIds.map((id, index) => ({
      id,
      type: "pipeline" as const,
      position: { x: index % 2 === 0 ? -8 : 684, y: index < 2 ? -8 : 176 },
      data: {},
      width: PIPELINE_BOUND_SIZE,
      height: PIPELINE_BOUND_SIZE,
      initialWidth: PIPELINE_BOUND_SIZE,
      initialHeight: PIPELINE_BOUND_SIZE,
      measured: {
        width: PIPELINE_BOUND_SIZE,
        height: PIPELINE_BOUND_SIZE,
      },
      draggable: false,
      selectable: false,
      focusable: false,
      connectable: false,
      className: "pipeline-bound-node",
      ariaLabel: "Pipeline fit boundary",
    })),
    ...flow.stages.map((stage) => ({
      id: stage.key,
      type: "pipeline" as const,
      position: positions[stage.key],
      data: { stage },
      width: PIPELINE_NODE_WIDTH,
      height: PIPELINE_NODE_HEIGHT,
      initialWidth: PIPELINE_NODE_WIDTH,
      initialHeight: PIPELINE_NODE_HEIGHT,
      measured: {
        width: PIPELINE_NODE_WIDTH,
        height: PIPELINE_NODE_HEIGHT,
      },
      draggable: false,
      selectable: false,
      focusable: false,
      connectable: false,
    })),
  ];
  const edges: PipelineEdge[] = [
    forwardEdge("code-validation", "code", "validation", stages.code.state),
    forwardEdge("validation-review", "validation", "review", stages.validation.state),
    forwardEdge("review-integration", "review", "integration", stages.review.state),
    feedbackEdge(
      "validation-code",
      "validation",
      "code",
      feedbackLoopLabel("validation", flow.loops.validation),
      flow.loops.validation > 0,
      "validation",
    ),
    feedbackEdge(
      "review-code",
      "review",
      "code",
      feedbackLoopLabel("review", flow.loops.review),
      flow.loops.review > 0,
      "review",
    ),
    feedbackEdge(
      "integration-code",
      "integration",
      "code",
      feedbackLoopLabel("integration", flow.loops.integration),
      flow.loops.integration > 0,
      "integration",
    ),
  ];
  return { nodes, edges };
}

function forwardEdge(id: string, source: TaskStageKey, target: TaskStageKey, state: TaskStageState): PipelineEdge {
  return {
    id,
    source,
    target,
    sourceHandle: "right",
    targetHandle: "left",
    type: "smoothstep",
    className: `pipeline-edge ${state}`,
    markerEnd: { type: MarkerType.ArrowClosed, color: state === "complete" || state === "active" ? "#0f62fe" : "#c6c6c6" },
    selectable: false,
  };
}

function feedbackEdge(
  id: string,
  source: TaskStageKey,
  target: TaskStageKey,
  label: string,
  active: boolean,
  kind: FeedbackEdgeKind,
): PipelineEdge {
  const above = kind === "review";
  const offset = kind === "integration" ? 46 : kind === "review" ? 34 : 24;
  return {
    id,
    source,
    target,
    sourceHandle: above ? "top-source" : "bottom-source",
    targetHandle: above ? "top-target" : "bottom-target",
    type: "smoothstep",
    label,
    className: `pipeline-edge feedback ${kind} ${active ? "active" : "muted"}`,
    pathOptions: { borderRadius: 18, offset },
    labelBgPadding: [6, 3],
    labelBgBorderRadius: 4,
    labelBgStyle: { fill: active ? "#edf5ff" : "#f4f4f4" },
    labelStyle: {
      fill: active ? "#002d9c" : "#6f6f6f",
      fontSize: 11,
      fontWeight: 700,
    },
    markerEnd: { type: MarkerType.ArrowClosed, color: active ? "#0f62fe" : "#c6c6c6" },
    selectable: false,
  };
}

function feedbackLoopLabel(kind: FeedbackEdgeKind, count: number) {
  return count > 0 ? `${kind} x${count}` : `${kind} feedback`;
}

function runArtifactIsLive(taskLive: boolean, run?: TaskRunArtifact | null): boolean {
  if (!taskLive || !run) return false;
  if (run.completed === true) return false;
  if (run.exit_code !== null && run.exit_code !== undefined) return false;
  return true;
}

function RouteIcon() {
  return <GitBranch size={17} />;
}

function AttemptStack({
  activeStage,
  attempts,
  iterationPatches,
  onLoadEarlierTranscript,
  onShowValidation,
  reviews,
  runTranscripts,
  task,
  validationLog,
  validationLogIndex,
}: {
  activeStage: ActiveStageInfo;
  attempts: TaskAttempt[];
  iterationPatches: Record<number, string>;
  onLoadEarlierTranscript: (runName: string) => void;
  onShowValidation: (index: number) => void;
  reviews: ReviewRecord[];
  runTranscripts: Record<string, TranscriptWindow>;
  task: TaskRecord;
  validationLog: string;
  validationLogIndex: number | null;
}) {
  if (!attempts.length) {
    return <section className="panel"><div className="empty-state">No worker, validation, or reviewer run has been captured yet.</div></section>;
  }
  return (
    <div className="attempt-stack page-stack">
      {[...attempts].reverse().map((attempt) => (
        <AttemptCard
          activeStage={activeStage}
          attempt={attempt}
          key={`${attempt.attempt}-${attempt.label}`}
          iterationPatch={iterationPatches[attempt.attempt] || ""}
          onLoadEarlierTranscript={onLoadEarlierTranscript}
          onShowValidation={onShowValidation}
          review={reviewForAttempt(attempt, reviews)}
          runTranscripts={runTranscripts}
          task={task}
          validationLog={validationLog}
          validationLogIndex={validationLogIndex}
        />
      ))}
    </div>
  );
}

function AttemptCard({
  activeStage,
  attempt,
  iterationPatch,
  onShowValidation,
  onLoadEarlierTranscript,
  review,
  runTranscripts,
  task,
  validationLog,
  validationLogIndex,
}: {
  activeStage: ActiveStageInfo;
  attempt: TaskAttempt;
  iterationPatch: string;
  onShowValidation: (index: number) => void;
  onLoadEarlierTranscript: (runName: string) => void;
  review?: ReviewRecord;
  runTranscripts: Record<string, TranscriptWindow>;
  task: TaskRecord;
  validationLog: string;
  validationLogIndex: number | null;
}) {
  const isActiveAttempt = activeStage.attempt?.attempt === attempt.attempt;
  const isLiveAttempt = activeStage.live && isActiveAttempt;
  const stageTab = activeStage.tab === "patch" ? "patch" : activeStage.tab;
  const [open, setOpen] = useState(isActiveAttempt);
  const [userCollapsed, setUserCollapsed] = useState(false);
  const [selectedTab, setSelectedTab] = useState<AttemptTab>("transcript");
  const [userSelectedTab, setUserSelectedTab] = useState(false);
  const visibleOpen = open || (isActiveAttempt && !userCollapsed);
  const active = isActiveAttempt && !userSelectedTab ? stageTab : selectedTab;
  const workerWindow = attempt.worker ? runTranscripts[attempt.worker.name] : undefined;
  const reviewerWindow = attempt.reviewer ? runTranscripts[attempt.reviewer.name] : undefined;
  const workerText = workerWindow?.text || "";
  const reviewerText = reviewerWindow?.text || "";
  const hasReview = Boolean(review || reviewerText);
  const visiblePatch = iterationPatch;
  const tabs: Array<{ key: AttemptTab; label: string; meta?: string | number; spinning?: boolean }> = [
    { key: "transcript", label: "Transcript", meta: workerText ? "live" : undefined, spinning: isLiveAttempt && activeStage.tab === "transcript" },
    { key: "patch", label: "Patch", meta: visiblePatch ? "saved" : undefined },
    { key: "validation", label: "Validation", meta: attempt.validations.length, spinning: isLiveAttempt && activeStage.tab === "validation" },
    { key: "review", label: "Review", meta: hasReview ? "ready" : undefined, spinning: isLiveAttempt && activeStage.tab === "review" },
  ];
  return (
    <article className={`attempt-card ${isActiveAttempt ? "active-run" : ""}`}>
      <button
        aria-expanded={visibleOpen}
        className="attempt-head"
        onClick={() => {
          const nextOpen = !visibleOpen;
          setOpen(nextOpen);
          setUserCollapsed(!nextOpen);
        }}
        type="button"
      >
        <div className="attempt-title">
          <ChevronRight className="attempt-chevron" size={16} />
          {isLiveAttempt && <Spinner />}
          <div>
            <span className="attempt-kicker mono">attempt {attempt.attempt}</span>
            <h3>{attempt.label}</h3>
          </div>
        </div>
        <div className="attempt-meta">
          <span>{attempt.worker ? "worker" : "no worker"}</span>
          <span>{attempt.validations.length} validations</span>
          <span>{attempt.reviewer ? "reviewed" : "not reviewed"}</span>
        </div>
      </button>
      {visibleOpen && (
        <div className="attempt-body">
          <div className="attempt-tabs" role="tablist" aria-label={`${attempt.label} run views`}>
            {tabs.map((tab) => (
              <button
                aria-selected={active === tab.key}
                className={active === tab.key ? "active" : ""}
                key={tab.key}
                onClick={() => {
                  setSelectedTab(tab.key);
                  setUserSelectedTab(true);
                }}
                role="tab"
                type="button"
              >
                {tab.spinning && <Spinner />}
                <span>{tab.label}</span>
                {tab.meta !== undefined && <b>{tab.meta}</b>}
              </button>
            ))}
          </div>
          <div className="attempt-panel">
            {active === "transcript" && (
              <RunSection
                diagnostics={attempt.worker?.diagnostics}
                emptyText="No worker transcript for this attempt."
                isLiveRun={activeStage.tab === "transcript" && runArtifactIsLive(isLiveAttempt, attempt.worker)}
                label="Worker transcript"
                onLoadEarlier={onLoadEarlierTranscript}
                prompt={attempt.attempt === 0 ? task.spec.prompt : ""}
                runName={attempt.worker?.name}
                taskId={`${task.spec.id}-${attempt.worker?.name || "worker"}`}
                text={workerText}
                transcriptWindow={workerWindow}
              />
            )}
            {active === "patch" && <RunPatchCard patch={visiblePatch} />}
            {active === "validation" && (
              <AttemptValidations log={validationLog} logIndex={validationLogIndex} onShow={onShowValidation} validations={attempt.validations} />
            )}
            {active === "review" && (
              <AttemptReview
                diagnostics={attempt.reviewer?.diagnostics}
                isLiveRun={activeStage.tab === "review" && runArtifactIsLive(isLiveAttempt, attempt.reviewer)}
                onLoadEarlier={onLoadEarlierTranscript}
                reviewerText={reviewerText}
                reviewerWindow={reviewerWindow}
                review={review}
                runName={attempt.reviewer?.name}
                taskId={`${task.spec.id}-${attempt.reviewer?.name || "reviewer"}`}
              />
            )}
          </div>
        </div>
      )}
    </article>
  );
}

function RunPatchCard({ patch }: { patch: string }) {
  return (
    <div className="run-patch">
      {patch ? <DiffView text={patch} /> : <div className="empty-state compact">No saved patch for this iteration.</div>}
    </div>
  );
}

function AttemptReview({
  diagnostics,
  isLiveRun,
  onLoadEarlier,
  reviewerText,
  reviewerWindow,
  review,
  runName,
  taskId,
}: {
  diagnostics?: CodexRunDiagnostics | null;
  isLiveRun: boolean;
  onLoadEarlier: (runName: string) => void;
  reviewerText: string;
  reviewerWindow?: TranscriptWindow;
  review?: ReviewRecord;
  runName?: string;
  taskId: string;
}) {
  return (
    <div className="attempt-review-stack">
      {review ? <ReviewCard review={review} /> : <div className="empty-state compact">No structured review verdict for this attempt.</div>}
      <RunSection
        diagnostics={diagnostics}
        emptyText="No reviewer transcript for this attempt."
        isLiveRun={isLiveRun}
        label="Reviewer transcript"
        onLoadEarlier={onLoadEarlier}
        prompt=""
        runName={runName}
        taskId={taskId}
        text={reviewerText}
        transcriptWindow={reviewerWindow}
      />
    </div>
  );
}

function RunSection({
  diagnostics,
  emptyText,
  isLiveRun = false,
  label,
  onLoadEarlier,
  prompt,
  runName,
  taskId,
  text,
  transcriptWindow,
}: {
  diagnostics?: CodexRunDiagnostics | null;
  emptyText: string;
  isLiveRun?: boolean;
  label: string;
  onLoadEarlier: (runName: string) => void;
  prompt: string;
  runName?: string;
  taskId: string;
  text: string;
  transcriptWindow?: TranscriptWindow;
}) {
  return (
    <>
      <div className="attempt-section-head">
        <FileText size={15} />
        <h4>{label}</h4>
        {runName && <code>{runName}</code>}
      </div>
      {text ? (
        <div className="attempt-transcript">
          {transcriptWindow && (
            <TranscriptWindowToolbar
              onLoadEarlier={() => runName && onLoadEarlier(runName)}
              window={transcriptWindow}
            />
          )}
          <TranscriptView diagnostics={diagnostics} isLiveRun={isLiveRun} prompt={prompt} taskId={taskId} text={text} />
        </div>
      ) : (
        <div className="empty-state compact">{emptyText}</div>
      )}
    </>
  );
}

function TranscriptWindowToolbar({
  onLoadEarlier,
  window,
}: {
  onLoadEarlier: () => void;
  window: TranscriptWindow;
}) {
  return (
    <div className="transcript-window-toolbar">
      <span>
        Showing {formatBytes(window.end - window.start)} of {formatBytes(window.size)}
      </span>
      {window.has_before && (
        <button className="button-inline" onClick={onLoadEarlier} type="button">
          Load Earlier
        </button>
      )}
    </div>
  );
}

function AttemptValidations({
  log,
  logIndex,
  onShow,
  validations,
}: {
  log: string;
  logIndex: number | null;
  onShow: (index: number) => void;
  validations: TaskAttempt["validations"];
}) {
  if (!validations.length) return <div className="empty-state compact">No validation is associated with this attempt.</div>;
  return (
    <div className="attempt-validation-list">
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

function ReviewCard({ review }: { review: ReviewRecord }) {
  return (
    <article className="review-card">
      <div className="review-head">
        <div>
          <div className="mono muted">{shortDate(review.created_at)} · attempt {review.attempt}</div>
          <h3>{review.summary || "Review completed"}</h3>
        </div>
        <span className={`review-verdict ${review.verdict === "approve" ? "approve" : review.verdict === "block" ? "block" : "fail"}`}>
          {review.verdict}
        </span>
      </div>
      <div className="review-facts">
        <KeyValue label="Event" value={review.event_kind} />
        {review.exit_code !== null && <KeyValue label="Exit" value={String(review.exit_code)} />}
        <KeyValue label="Findings" value={String(review.findings.length)} />
        <KeyValue label="Validation gaps" value={String(review.validation_gaps.length)} />
      </div>
      {review.remaining_risk && (
        <section className="review-note">
          <h4>Remaining Risk</h4>
          <p>{review.remaining_risk}</p>
        </section>
      )}
      {review.command && (
        <section className="review-note">
          <h4>Command</h4>
          <p className="mono">{review.command}</p>
        </section>
      )}
      {review.findings.length > 0 && (
        <>
          <h4>Findings</h4>
          <div className="review-findings">
            {review.findings.map((finding, index) => (
              <div className="review-finding" key={`${finding.file}-${finding.line}-${index}`}>
                <div className="review-finding-title">
                  <span className={`severity severity-${finding.severity}`}>{finding.severity}</span>
                  <b>{finding.title}</b>
                </div>
                <div className="mono muted">
                  {finding.file}{finding.line !== null ? `:${finding.line}` : ""}
                </div>
                <p>{finding.detail}</p>
                <p><b>Recommendation:</b> {finding.recommendation}</p>
              </div>
            ))}
          </div>
        </>
      )}
      {review.validation_gaps.length > 0 && (
        <>
          <h4>Validation Gaps</h4>
          <ul className="review-gaps">
            {review.validation_gaps.map((gap, index) => <li key={`${gap}-${index}`}>{gap}</li>)}
          </ul>
        </>
      )}
    </article>
  );
}

function DiffView({ text }: { text: string }) {
  if (!text) return <div className="empty-state">No saved patch for the selected task.</div>;
  return <CodeBlock diffDisplay="unified-with-split-modal" language="diff" text={text} title="Patch" />;
}

function KeyValue({ label, value }: { label: string; value: string }) {
  return (
    <div className="key-value">
      <span>{label}</span>
      <b className="mono">{value}</b>
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

function Spinner() {
  return <span className="live-spinner" aria-label="active" />;
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

function taskFlow(task: TaskRecord, attempts: TaskAttempt[], events: EventRecord[]) {
  const active = activeStage(task, attempts, events);
  const loops = flowLoops(events);
  const hasWorker = attempts.some((attempt) => Boolean(attempt.worker));
  const hasValidation = attempts.some((attempt) => attempt.validations.length > 0);
  const hasReview = attempts.some((attempt) => Boolean(attempt.reviewer || attempt.review));
  const hasIntegration = events.some((event) => event.kind.startsWith("integration.") || event.kind === "main.pushed")
    || task.status === "integrating"
    || task.status === "pushed";
  const blocked = new Set<TaskStageKey>();
  if (["blocked", "failed", "cancelled"].includes(task.status)) blocked.add(active.key);
  const stages: TaskStage[] = [
    {
      key: "code",
      label: "Code Generation",
      state: stageState("code", active, hasWorker, blocked),
      detail: stageDetail("code", events, hasWorker),
    },
    {
      key: "validation",
      label: "Validation",
      state: stageState("validation", active, hasValidation, blocked),
      detail: stageDetail("validation", events, hasValidation),
    },
    {
      key: "review",
      label: "Review",
      state: stageState("review", active, hasReview, blocked),
      detail: stageDetail("review", events, hasReview),
    },
    {
      key: "integration",
      label: "Integration",
      state: stageState("integration", active, hasIntegration, blocked),
      detail: stageDetail("integration", events, hasIntegration),
    },
  ];
  return { stages, active, loops };
}

function activeStage(task: TaskRecord, attempts: TaskAttempt[], events: EventRecord[]): ActiveStageInfo {
  const attempt = attempts.length ? attempts[attempts.length - 1] : null;
  const latestEvent = [...events].reverse().find((event) => eventStage(event) !== null);
  const live = taskIsLive(task.status);
  if (task.status === "integrating" || task.status === "pushed" || latestEvent?.kind.startsWith("integration.") || latestEvent?.kind === "main.pushed") {
    return {
      key: "integration",
      attempt,
      live,
      tab: "patch",
    };
  }
  if (task.status === "reviewing" || eventStage(latestEvent) === "review") {
    return {
      key: "review",
      attempt,
      live,
      tab: "review",
    };
  }
  if (eventStage(latestEvent) === "validation") {
    return {
      key: "validation",
      attempt,
      live,
      tab: "validation",
    };
  }
  return {
    key: "code",
    attempt,
    live,
    tab: "transcript",
  };
}

function stageState(
  key: TaskStageKey,
  active: ActiveStageInfo,
  complete: boolean,
  blocked: Set<TaskStageKey>,
): TaskStageState {
  if (blocked.has(key)) return "blocked";
  if (key === active.key && active.live) return "active";
  return complete ? "complete" : "pending";
}

function stageDetail(key: TaskStageKey, events: EventRecord[], complete: boolean) {
  const event = [...events].reverse().find((item) => eventStage(item) === key);
  if (!event) return fallbackStageDetail(key, complete);
  if (key === "review") return reviewStageDetail(event);
  if (key === "validation") return validationStageDetail(event);
  if (key === "code") return codeStageDetail(event);
  if (key === "integration") return integrationStageDetail(event);
  return fallbackStageDetail(key, complete);
}

function fallbackStageDetail(key: TaskStageKey, complete: boolean) {
  if (key === "code") return complete ? "Worker session captured" : "Waiting for worker";
  if (key === "validation") return complete ? "Validation gates recorded" : "No validation run yet";
  if (key === "review") return complete ? "Reviewer verdict recorded" : "Waiting for review";
  return complete ? "Integration activity recorded" : "Waiting for integration";
}

function reviewStageDetail(event: EventRecord) {
  if (event.kind === "review.finished") {
    const review = reviewPayload(event);
    const verdict = stringValue(review.verdict, "finished");
    const findings = Array.isArray(review.findings) ? review.findings.length : 0;
    const gaps = Array.isArray(review.validation_gaps) ? review.validation_gaps.length : 0;
    return `Review ${verdict} · ${findings} finding(s) · ${gaps} gap(s)`;
  }
  if (event.kind === "review.invalid_output") return "Review returned invalid output";
  if (event.kind === "review.failed") return "Review failed";
  return "Review in progress";
}

function validationStageDetail(event: EventRecord) {
  if (event.kind === "validation.failed") return "Validation failed";
  if (event.kind === "patch.saved") return "Patch saved after validation";
  return "Validation updated";
}

function codeStageDetail(event: EventRecord) {
  if (event.kind === "worker.revision_requested") return "Review requested a worker revision";
  if (event.kind === "worker.validation_revision_requested") return "Validation requested a worker revision";
  if (event.kind === "worker.integration_revision_requested") return "Integration requested a worker revision";
  if (event.kind.endsWith("_finished") || event.kind === "worker.finished") return `Worker finished · exit ${event.message}`;
  if (event.kind === "worktree.ready") return "Worktree ready";
  return "Worker activity recorded";
}

function integrationStageDetail(event: EventRecord) {
  if (event.kind === "main.pushed") return `Pushed ${shortSha(event.message)}`;
  if (event.kind === "integration.queued") return "Integration queued";
  if (event.kind === "integration.started") return "Integration started";
  return "Integration activity recorded";
}

function flowLoops(events: EventRecord[]) {
  return {
    validation: events.filter((event) => event.kind === "worker.validation_revision_requested").length,
    review: events.filter((event) => event.kind === "worker.revision_requested").length,
    integration: events.filter((event) => event.kind === "worker.integration_revision_requested").length,
  };
}

function eventStage(event?: EventRecord): TaskStageKey | null {
  const kind = event?.kind || "";
  const phase = stringValue(event?.data?.phase, "");
  if (kind === "task.status" && phase === "validation") return "validation";
  if (kind.startsWith("worker.") || kind === "worker.finished" || kind === "worktree.ready") return "code";
  if (kind.startsWith("validation.") || kind === "patch.saved") return "validation";
  if (kind.startsWith("review.")) return "review";
  if (kind.startsWith("integration.") || kind === "main.pushed") return "integration";
  return null;
}

function stageIcon(state: TaskStageState) {
  if (state === "complete") return <CheckCircle2 size={15} />;
  if (state === "blocked") return <XCircle size={15} />;
  return <Circle size={12} />;
}

function taskIsLive(status: TaskStatus) {
  return ["queued", "running", "reviewing", "integrating"].includes(status);
}

function reviewRecords(events: EventRecord[]): ReviewRecord[] {
  return events
    .filter((event) => ["review.finished", "review.failed", "review.invalid_output"].includes(event.kind))
    .map((event, index) => {
      const review = reviewPayload(event);
      const isFinished = event.kind === "review.finished";
      return {
        attempt: reviewAttempt(event, index),
        created_at: event.created_at,
        event_kind: event.kind,
        verdict: isFinished ? stringValue(review.verdict, "unknown") : event.kind === "review.failed" ? "failed" : "invalid",
        summary: isFinished ? stringValue(review.summary, event.message) : event.message || event.kind,
        findings: isFinished ? findingArray(review.findings) : [],
        validation_gaps: isFinished ? stringArray(review.validation_gaps) : [],
        remaining_risk: isFinished ? stringValue(review.remaining_risk, "") : "",
        exit_code: numberValue(event.data.exit_code),
        command: commandValue(event.data.command),
      };
    });
}

function reviewForAttempt(attempt: TaskAttempt, reviews: ReviewRecord[]): ReviewRecord | undefined {
  const stored = attempt.review;
  if (isRecord(stored)) {
    return {
      attempt: attempt.attempt,
      created_at: attempt.reviewer?.updated_at || "",
      event_kind: "iteration.review",
      verdict: stringValue(stored.verdict, "unknown"),
      summary: stringValue(stored.summary, ""),
      findings: findingArray(stored.findings),
      validation_gaps: stringArray(stored.validation_gaps),
      remaining_risk: stringValue(stored.remaining_risk, ""),
      exit_code: attempt.reviewer?.exit_code ?? null,
      command: "",
    };
  }
  return reviews.find((item) => item.attempt === attempt.attempt);
}

function reviewPayload(event: EventRecord): Record<string, unknown> {
  if (isRecord(event.data.review)) return event.data.review;
  try {
    const parsed = JSON.parse(event.message) as unknown;
    return isRecord(parsed) ? parsed : {};
  } catch {
    return {};
  }
}

function reviewAttempt(event: EventRecord, fallback: number) {
  return numberValue(event.data.attempt) ?? fallback;
}

function findingArray(value: unknown): ReviewFinding[] {
  if (!Array.isArray(value)) return [];
  return value.filter(isRecord).map((item) => ({
    severity: stringValue(item.severity, "medium"),
    title: stringValue(item.title, "Finding"),
    file: stringValue(item.file, ""),
    line: numberValue(item.line),
    detail: stringValue(item.detail, ""),
    recommendation: stringValue(item.recommendation, ""),
  }));
}

function stringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.map((item) => String(item)) : [];
}

function commandValue(value: unknown): string {
  return Array.isArray(value) ? value.map((item) => String(item)).join(" ") : "";
}

function stringValue(value: unknown, fallback: string) {
  return typeof value === "string" && value.trim() ? value : fallback;
}

function numberValue(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function shortDate(value: string) {
  if (!value) return "-";
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "short",
    timeStyle: "medium",
  }).format(new Date(value));
}

function shortSha(value: string) {
  return value.length > 12 ? value.slice(0, 12) : value;
}

function mergeTranscriptMaps(
  previous: Record<string, TranscriptWindow>,
  next: Record<string, TranscriptWindow>,
): Record<string, TranscriptWindow> {
  const merged = { ...previous };
  for (const [name, window] of Object.entries(next)) {
    merged[name] = mergeTranscriptWindows(previous[name], window);
  }
  return merged;
}

function mergeTranscriptWindows(
  previous: TranscriptWindow | undefined,
  next: TranscriptWindow,
): TranscriptWindow {
  if (!previous || !previous.text) return next;
  if (!next.text) return previous;
  if (next.start <= previous.start && next.end >= previous.end) return next;
  if (previous.start <= next.start && previous.end >= next.end) {
    return { ...previous, size: next.size, has_after: previous.end < next.size };
  }
  if (next.end <= previous.start) {
    return {
      text: next.text + previous.text,
      start: next.start,
      end: previous.end,
      size: Math.max(previous.size, next.size),
      has_before: next.has_before,
      has_after: previous.has_after,
    };
  }
  if (previous.end <= next.start) {
    return {
      text: previous.text + next.text,
      start: previous.start,
      end: next.end,
      size: Math.max(previous.size, next.size),
      has_before: previous.has_before,
      has_after: next.has_after,
    };
  }
  if (next.start < previous.start) {
    return {
      text: next.text + previous.text.slice(next.end - previous.start),
      start: next.start,
      end: previous.end,
      size: Math.max(previous.size, next.size),
      has_before: next.has_before,
      has_after: previous.has_after,
    };
  }
  return {
    text: previous.text + next.text.slice(previous.end - next.start),
    start: previous.start,
    end: next.end,
    size: Math.max(previous.size, next.size),
    has_before: previous.has_before,
    has_after: next.has_after,
  };
}

function transcriptWindowLimit(window: TranscriptWindow) {
  return Math.max(1, window.end - window.start);
}

function formatBytes(value: number) {
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KiB`;
  return `${(value / (1024 * 1024)).toFixed(1)} MiB`;
}

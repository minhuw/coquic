import type {
  CloudArtifact,
  CloudDisclosure,
  CloudEvent,
  CloudPipeline,
  CloudRun,
  CloudTaskDetail,
  CloudTaskSummary,
  CloudTrajectoryDescriptor,
} from "./cloud-schema";

/**
 * The mapper consumes the repository's already validated graph. It deliberately
 * has no repository, filesystem, or network dependency so the page cannot
 * recreate archive heuristics while rendering.
 */
export type CloudTaskViewInput = CloudTaskDetail;

export interface CloudTaskViewTask {
  readonly id: string;
  readonly title: string;
  readonly status: CloudTaskSummary["lifecycleState"];
  readonly createdAt: string;
  readonly completedAt: string | null;
  readonly pipelineId: string | null;
  readonly completedRunId: string | null;
  readonly eventCount: number;
  readonly artifactCount: number;
  readonly disclosure: CloudDisclosure;
}

export interface CloudPipelineView extends CloudPipeline {
  readonly runIds: readonly string[];
}

export interface CloudRunTiming {
  readonly startedAt: string;
  readonly completedAt: string;
  readonly durationMs: number | null;
  readonly durationSeconds: number | null;
}

export interface CloudRunView {
  readonly runId: string;
  readonly taskId: string;
  readonly pipelineId: string;
  readonly role: string;
  readonly status: CloudRun["runState"];
  readonly runState: CloudRun["runState"];
  readonly timing: CloudRunTiming | null;
  readonly atifDigest: string;
  readonly atifArtifactId: string | null;
  /** Usage is not part of the public cloud graph and must not be invented. */
  readonly usage: null;
}

export interface CloudEventView {
  readonly id: string;
  readonly taskId: string;
  readonly sequence: number;
  readonly eventType: string;
  readonly kind: string;
  readonly occurredAt: string;
  readonly timestamp: string;
  readonly summary: string;
}

export interface CloudArtifactAction {
  readonly kind: "download" | "trajectory";
  readonly artifactId: string;
  readonly taskId: string;
  readonly runId: string;
  readonly logicalPath: string;
}

export interface CloudArtifactView extends CloudArtifact {
  readonly action: CloudArtifactAction | null;
}

export type CloudTrajectoryView =
  | {
      readonly state: "available";
      readonly descriptor: CloudTrajectoryDescriptor;
      readonly action: CloudArtifactAction;
    }
  | {
      readonly state: "placeholder";
      readonly descriptor: null;
      readonly action: null;
      readonly reason: "no-completed-run" | "artifact-unavailable";
    };

export interface CloudAttemptView {
  readonly number: number;
  readonly pipelineId: string;
  readonly label: string;
  readonly status: CloudRun["runState"] | "unavailable";
  readonly startedAt: string | null;
  readonly completedAt: string | null;
  readonly durationMs: number | null;
  readonly durationSeconds: number | null;
  readonly runIds: readonly string[];
  readonly runs: readonly CloudRunView[];
}

export interface CloudTimelineView {
  readonly id: string;
  readonly stage: "task";
  readonly kind: string;
  readonly timestamp: string;
  readonly title: string;
  readonly detail: string;
}

export interface CloudTaskCompleteness {
  /** The repository graph is all-or-nothing, even when its trajectory is absent. */
  readonly state: "complete";
  readonly trajectory: CloudTrajectoryView["state"];
  readonly warnings: readonly string[];
}

export interface CloudTaskViewModel {
  readonly task: CloudTaskViewTask;
  readonly pipelines: readonly CloudPipelineView[];
  readonly runs: readonly CloudRunView[];
  readonly attempts: readonly CloudAttemptView[];
  readonly events: readonly CloudEventView[];
  readonly timeline: readonly CloudTimelineView[];
  readonly artifacts: readonly CloudArtifactView[];
  readonly trajectory: CloudTrajectoryView;
  readonly completeness: CloudTaskCompleteness;
}

function durationFromTimestamps(startedAt: string, completedAt: string): number | null {
  const start = Date.parse(startedAt);
  const end = Date.parse(completedAt);
  if (!Number.isFinite(start) || !Number.isFinite(end) || end < start) return null;
  const duration = end - start;
  return Number.isSafeInteger(duration) ? duration : null;
}

function runTiming(run: CloudRun): CloudRunTiming | null {
  const timestampDuration = durationFromTimestamps(run.startedAt, run.completedAt);
  if (timestampDuration === null) return null;
  const durationMs = Number.isSafeInteger(run.durationMs) && run.durationMs >= 0
    ? run.durationMs
    : timestampDuration;
  const durationSeconds = durationMs === null ? null : Math.floor(durationMs / 1_000);
  return { startedAt: run.startedAt, completedAt: run.completedAt, durationMs, durationSeconds };
}

function mapTask(task: CloudTaskSummary): CloudTaskViewTask {
  return {
    id: task.taskId,
    title: task.title,
    status: task.lifecycleState,
    createdAt: task.createdAt,
    completedAt: task.completedAt,
    pipelineId: task.pipelineId,
    completedRunId: task.completedRunId,
    eventCount: task.eventCount,
    artifactCount: task.artifactCount,
    disclosure: task.disclosure,
  };
}

function mapRun(run: CloudRun): CloudRunView {
  return {
    runId: run.runId,
    taskId: run.taskId,
    pipelineId: run.pipelineId,
    role: run.role,
    status: run.runState,
    runState: run.runState,
    timing: runTiming(run),
    atifDigest: run.atifDigest,
    atifArtifactId: run.atifArtifactId ?? null,
    usage: null,
  };
}

function mapArtifact(artifact: CloudArtifact, trajectoryArtifactId: string | null): CloudArtifactView {
  const isTrajectory = trajectoryArtifactId === artifact.artifactId;
  return {
    ...artifact,
    action: artifact.availability === "available"
      ? {
          kind: isTrajectory ? "trajectory" : "download",
          artifactId: artifact.artifactId,
          taskId: artifact.taskId,
          runId: artifact.runId,
          logicalPath: artifact.logicalPath,
        }
      : null,
  };
}

function mapEvent(event: CloudEvent): CloudEventView {
  const id = `${event.taskId}:event-${event.sequence}`;
  return {
    id,
    taskId: event.taskId,
    sequence: event.sequence,
    eventType: event.eventType,
    kind: event.eventType,
    occurredAt: event.occurredAt,
    timestamp: event.occurredAt,
    summary: event.summary,
  };
}

function pipelineStatus(runs: readonly CloudRunView[]): CloudAttemptView["status"] {
  if (!runs.length) return "unavailable";
  if (runs.some((run) => run.status === "failed")) return "failed";
  if (runs.some((run) => run.status === "cancelled")) return "cancelled";
  return "completed";
}

function pipelineTiming(runs: readonly CloudRunView[]): Pick<CloudAttemptView, "startedAt" | "completedAt" | "durationMs" | "durationSeconds"> {
  const timed = runs.map((run) => run.timing).filter((timing): timing is CloudRunTiming => timing !== null);
  if (!timed.length) return { startedAt: null, completedAt: null, durationMs: null, durationSeconds: null };
  const startedAt = timed.reduce((earliest, timing) => timing.startedAt < earliest ? timing.startedAt : earliest, timed[0]!.startedAt);
  const completedAt = timed.reduce((latest, timing) => timing.completedAt > latest ? timing.completedAt : latest, timed[0]!.completedAt);
  const durationMs = durationFromTimestamps(startedAt, completedAt);
  return { startedAt, completedAt, durationMs, durationSeconds: durationMs === null ? null : Math.floor(durationMs / 1_000) };
}

function mapAttempt(number: number, pipeline: CloudPipeline, runs: readonly CloudRunView[]): CloudAttemptView {
  const timing = pipelineTiming(runs);
  return {
    number,
    pipelineId: pipeline.pipelineId,
    label: pipeline.name,
    status: pipelineStatus(runs),
    ...timing,
    runIds: runs.map((run) => run.runId),
    runs,
  };
}

function placeholder(task: CloudTaskSummary): CloudTrajectoryView {
  return task.completedRunId === null
    ? { state: "placeholder", descriptor: null, action: null, reason: "no-completed-run" }
    : { state: "placeholder", descriptor: null, action: null, reason: "artifact-unavailable" };
}

function trajectoryArtifact(detail: CloudTaskDetail, descriptor: CloudTrajectoryDescriptor): CloudArtifact | null {
  return detail.artifacts.find((artifact) => artifact.runId === descriptor.runId
    && artifact.publicKey === descriptor.publicKey
    && artifact.sha256 === descriptor.sha256
    && artifact.mediaType === descriptor.mediaType
    && artifact.availability === "available") ?? null;
}

/** Project one validated cloud detail graph into a page-ready, byte-free model. */
export function buildCloudTaskViewModel(detail: CloudTaskViewInput): CloudTaskViewModel {
  const runs = detail.runs.map(mapRun);
  const runsByPipeline = new Map<string, CloudRunView[]>();
  for (const run of runs) {
    const pipelineRuns = runsByPipeline.get(run.pipelineId) ?? [];
    pipelineRuns.push(run);
    runsByPipeline.set(run.pipelineId, pipelineRuns);
  }
  const pipelines = detail.pipelines.map((pipeline) => ({
    ...pipeline,
    runIds: (runsByPipeline.get(pipeline.pipelineId) ?? []).map((run) => run.runId),
  }));
  const attempts = pipelines.map((pipeline, number) => mapAttempt(number, pipeline, runsByPipeline.get(pipeline.pipelineId) ?? []));
  const selectedTrajectoryArtifact = detail.trajectory === null ? null : trajectoryArtifact(detail, detail.trajectory);
  const trajectory = detail.trajectory === null || selectedTrajectoryArtifact === null
    ? placeholder(detail.task)
    : {
        state: "available" as const,
        descriptor: detail.trajectory,
        action: {
          kind: "trajectory" as const,
          artifactId: selectedTrajectoryArtifact.artifactId,
          taskId: selectedTrajectoryArtifact.taskId,
          runId: selectedTrajectoryArtifact.runId,
          logicalPath: selectedTrajectoryArtifact.logicalPath,
        },
      };
  const artifacts = detail.artifacts.map((artifact) => mapArtifact(artifact, selectedTrajectoryArtifact?.artifactId ?? null));
  const events = detail.events.map(mapEvent);
  const warnings = trajectory.state === "placeholder"
    ? [trajectory.reason === "no-completed-run" ? "No completed run has a public trajectory descriptor." : "The completed run trajectory artifact is unavailable."]
    : [];
  return {
    task: mapTask(detail.task),
    pipelines,
    runs,
    attempts,
    events,
    timeline: events.map((event) => ({ id: event.id, stage: "task" as const, kind: event.kind, timestamp: event.timestamp, title: event.eventType, detail: event.summary })),
    artifacts,
    trajectory,
    completeness: { state: "complete", trajectory: trajectory.state, warnings },
  };
}

export const projectCloudTask = buildCloudTaskViewModel;
export const mapCloudTaskDetail = buildCloudTaskViewModel;

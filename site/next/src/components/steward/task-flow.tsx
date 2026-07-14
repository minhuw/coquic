'use client';

import '@xyflow/react/dist/style.css';

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
} from '@xyflow/react';
import { Circle, CheckCircle2, GitBranch, XCircle } from 'lucide-react';

import { PanelTitle, shortSha } from './shared';
import type {
  PublicStewardEvent,
  PublicStewardTaskDetail,
  PublicTaskFlow,
  PublicTaskStage,
  PublicTaskStageKey,
  PublicTaskStageState,
} from './types';

type PublicPipelineNodeData = {
  stage?: PublicTaskStage;
};
type PublicPipelineNode = Node<PublicPipelineNodeData, 'pipeline'>;
type PublicPipelineEdge = Edge<Record<string, never>, 'smoothstep'> & {
  pathOptions?: SmoothStepPathOptions;
};

export function TaskFlowPanel({ flow }: { flow: PublicTaskFlow }) {
  const graph = publicPipelineGraph(flow);
  return (
    <section className="panel task-flow-panel" aria-label="Task iteration flow">
      <PanelTitle icon={<GitBranch size={17} />} title="Current Iteration" />
      <div className="pipeline-graph" aria-label="Task pipeline graph" role="region" tabIndex={0}>
        <ReactFlow
          defaultViewport={{ x: 34, y: 18, zoom: 1 }}
          edges={graph.edges}
          edgesFocusable={false}
          elementsSelectable={false}
          fitView={false}
          maxZoom={1}
          minZoom={1}
          nodeTypes={publicPipelineNodeTypes}
          nodes={graph.nodes}
          nodesConnectable={false}
          nodesDraggable={false}
          nodesFocusable={false}
          panOnDrag={false}
          panOnScroll={false}
          preventScrolling={false}
          proOptions={{ hideAttribution: true }}
          style={{ width: '760px', height: '206px' }}
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

const PUBLIC_PIPELINE_NODE_WIDTH = 150;
const PUBLIC_PIPELINE_NODE_HEIGHT = 76;
const PUBLIC_PIPELINE_BOUND_SIZE = 1;

const publicPipelineNodeTypes = {
  pipeline: PublicPipelineNodeCard,
};

function PublicPipelineNodeCard({ data }: NodeProps<PublicPipelineNode>) {
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
        <span className="pipeline-node-dot">{stage.state === 'active' ? <Spinner /> : stageIcon(stage.state)}</span>
        <b>{stage.label}</b>
      </div>
      <p>{stage.detail}</p>
    </article>
  );
}

export function publicPipelineGraph(flow: PublicTaskFlow): { nodes: PublicPipelineNode[]; edges: PublicPipelineEdge[] } {
  const fitBoundIds = ['fit-top-left', 'fit-top-right', 'fit-bottom-left', 'fit-bottom-right'];
  const hasPlan = flow.stages.some((stage) => stage.key === 'plan');
  const positions: Record<PublicTaskStageKey, { x: number; y: number }> = hasPlan
    ? {
        plan: { x: 0, y: 52 },
        code: { x: 142, y: 52 },
        validation: { x: 284, y: 52 },
        review: { x: 426, y: 52 },
        integration: { x: 568, y: 52 },
      }
    : {
        plan: { x: 0, y: 52 },
        code: { x: 0, y: 52 },
        validation: { x: 178, y: 52 },
        review: { x: 356, y: 52 },
        integration: { x: 534, y: 52 },
      };
  const stages = Object.fromEntries(flow.stages.map((stage) => [stage.key, stage])) as Record<PublicTaskStageKey, PublicTaskStage>;
  const nodes: PublicPipelineNode[] = [
    ...fitBoundIds.map((id, index) => ({
      id,
      type: 'pipeline' as const,
      position: { x: index % 2 === 0 ? -8 : 684, y: index < 2 ? -8 : 176 },
      data: {},
      width: PUBLIC_PIPELINE_BOUND_SIZE,
      height: PUBLIC_PIPELINE_BOUND_SIZE,
      initialWidth: PUBLIC_PIPELINE_BOUND_SIZE,
      initialHeight: PUBLIC_PIPELINE_BOUND_SIZE,
      measured: {
        width: PUBLIC_PIPELINE_BOUND_SIZE,
        height: PUBLIC_PIPELINE_BOUND_SIZE,
      },
      draggable: false,
      selectable: false,
      focusable: false,
      connectable: false,
      className: 'pipeline-bound-node',
    })),
    ...flow.stages.map((stage) => ({
      id: stage.key,
      type: 'pipeline' as const,
      position: positions[stage.key],
      data: { stage },
      width: PUBLIC_PIPELINE_NODE_WIDTH,
      height: PUBLIC_PIPELINE_NODE_HEIGHT,
      initialWidth: PUBLIC_PIPELINE_NODE_WIDTH,
      initialHeight: PUBLIC_PIPELINE_NODE_HEIGHT,
      measured: {
        width: PUBLIC_PIPELINE_NODE_WIDTH,
        height: PUBLIC_PIPELINE_NODE_HEIGHT,
      },
      draggable: false,
      selectable: false,
      focusable: false,
      connectable: false,
    })),
  ];
  const edges: PublicPipelineEdge[] = [
    ...(hasPlan ? [publicForwardEdge('plan-code', 'plan', 'code', stages.plan.state)] : []),
    publicForwardEdge('code-validation', 'code', 'validation', stages.code.state),
    publicForwardEdge('validation-review', 'validation', 'review', stages.validation.state),
    publicForwardEdge('review-integration', 'review', 'integration', stages.review.state),
    publicFeedbackEdge('validation-code', 'validation', 'code', publicFeedbackLoopLabel('validation', flow.loops.validation), flow.loops.validation > 0, 'validation'),
    publicFeedbackEdge('review-code', 'review', 'code', publicFeedbackLoopLabel('review', flow.loops.review), flow.loops.review > 0, 'review'),
    publicFeedbackEdge('integration-code', 'integration', 'code', publicFeedbackLoopLabel('integration', flow.loops.integration), flow.loops.integration > 0, 'integration'),
  ];
  return { nodes, edges };
}

function publicForwardEdge(
  id: string,
  source: PublicTaskStageKey,
  target: PublicTaskStageKey,
  state: PublicTaskStageState,
): PublicPipelineEdge {
  return {
    id,
    source,
    target,
    sourceHandle: 'right',
    targetHandle: 'left',
    type: 'smoothstep',
    className: `pipeline-edge ${state}`,
    markerEnd: { type: MarkerType.ArrowClosed, color: state === 'complete' || state === 'active' ? '#0f62fe' : '#c6c6c6' },
    selectable: false,
  };
}

function publicFeedbackEdge(
  id: string,
  source: PublicTaskStageKey,
  target: PublicTaskStageKey,
  label: string,
  active: boolean,
  kind: 'integration' | 'review' | 'validation',
): PublicPipelineEdge {
  const above = kind === 'review';
  const offset = kind === 'integration' ? 46 : kind === 'review' ? 34 : 24;
  return {
    id,
    source,
    target,
    sourceHandle: above ? 'top-source' : 'bottom-source',
    targetHandle: above ? 'top-target' : 'bottom-target',
    type: 'smoothstep',
    label,
    className: `pipeline-edge feedback ${kind} ${active ? 'active' : 'muted'}`,
    pathOptions: { borderRadius: 18, offset },
    labelBgPadding: [6, 3],
    labelBgBorderRadius: 4,
    labelBgStyle: { fill: active ? '#edf5ff' : '#f4f4f4' },
    labelStyle: {
      fill: active ? '#002d9c' : '#6f6f6f',
      fontSize: 11,
      fontWeight: 700,
    },
    markerEnd: { type: MarkerType.ArrowClosed, color: active ? '#0f62fe' : '#c6c6c6' },
    selectable: false,
  };
}

function publicFeedbackLoopLabel(kind: 'integration' | 'review' | 'validation', count: number) {
  return count > 0 ? `${kind} x${count}` : `${kind} feedback`;
}

export function publicTaskFlow(detail: PublicStewardTaskDetail): PublicTaskFlow {
  const task = detail.task;
  const attempts = detail.attempts;
  const events = detail.events;
  const activeKey = publicActiveStage(task.status, events);
  const featureWorkflow = task.workflow === 'feature' || task.spec.workflow === 'feature' || task.kind === 'feature';
  const hasPlan = events.some((event) => event.kind === 'implementation_plan.finished');
  const hasWorker = attempts.some((attempt) => Boolean(attempt.worker));
  const hasValidation = attempts.some((attempt) => attempt.validations.length > 0);
  const hasReview = attempts.some((attempt) => Boolean(attempt.reviewer || attempt.review));
  const hasIntegration = task.status === 'integrating'
    || task.status === 'pushed'
    || events.some((event) => event.kind.startsWith('integration.') || event.kind === 'main.pushed');
  const blocked = ['blocked', 'failed', 'cancelled'].includes(task.status) ? activeKey : null;
  const stages: PublicTaskStage[] = [
    ...(featureWorkflow ? [{
      detail: publicStageDetail('plan', events, hasPlan),
      key: 'plan' as const,
      label: 'Plan',
      state: publicStageState('plan', activeKey, hasPlan, blocked, task.status),
    }] : []),
    {
      detail: publicStageDetail('code', events, hasWorker),
      key: 'code',
      label: 'Code Generation',
      state: publicStageState('code', activeKey, hasWorker, blocked, task.status),
    },
    {
      detail: publicStageDetail('validation', events, hasValidation),
      key: 'validation',
      label: 'Validation',
      state: publicStageState('validation', activeKey, hasValidation, blocked, task.status),
    },
    {
      detail: publicStageDetail('review', events, hasReview),
      key: 'review',
      label: 'Review',
      state: publicStageState('review', activeKey, hasReview, blocked, task.status),
    },
    {
      detail: publicStageDetail('integration', events, hasIntegration),
      key: 'integration',
      label: 'Integration',
      state: publicStageState('integration', activeKey, hasIntegration, blocked, task.status),
    },
  ];
  return {
    activeKey,
    loops: {
      integration: events.filter((event) => event.kind === 'worker.integration_revision_requested').length,
      review: events.filter((event) => event.kind === 'worker.revision_requested').length,
      validation: events.filter((event) => event.kind === 'worker.validation_revision_requested').length,
    },
    stages,
  };
}

function publicActiveStage(status: string, events: PublicStewardEvent[]): PublicTaskStageKey {
  const latestEvent = [...events].reverse().find((event) => publicEventStage(event) !== null);
  if (status === 'integrating' || status === 'pushed' || latestEvent?.kind.startsWith('integration.') || latestEvent?.kind === 'main.pushed') return 'integration';
  if (status === 'reviewing' || publicEventStage(latestEvent) === 'review') return 'review';
  if (publicEventStage(latestEvent) === 'validation') return 'validation';
  if (publicEventStage(latestEvent) === 'plan') return 'plan';
  return 'code';
}

function publicStageState(
  key: PublicTaskStageKey,
  activeKey: PublicTaskStageKey,
  complete: boolean,
  blocked: PublicTaskStageKey | null,
  status: string,
): PublicTaskStageState {
  if (blocked === key) return 'blocked';
  if (key === activeKey && ['queued', 'running', 'reviewing', 'integrating'].includes(status)) return 'active';
  return complete ? 'complete' : 'pending';
}

function publicStageDetail(key: PublicTaskStageKey, events: PublicStewardEvent[], complete: boolean) {
  const event = [...events].reverse().find((item) => publicEventStage(item) === key);
  if (!event) return publicFallbackStageDetail(key, complete);
  if (key === 'plan') {
    if (event.kind === 'implementation_plan.finished') return 'Implementation plan ready';
    if (event.kind === 'implementation_plan.invalid_output') return 'Planner returned invalid output';
    if (event.kind === 'implementation_plan.failed') return 'Implementation planning failed';
    return 'Implementation planning in progress';
  }
  if (key === 'code') {
    if (event.kind === 'worktree.ready') return 'Worktree ready';
    if (event.kind.includes('revision_requested')) return 'Revision requested';
    if (event.kind.includes('finished')) return event.message || 'Worker finished';
    return 'Worker activity recorded';
  }
  if (key === 'validation') {
    if (event.kind === 'validation.failed') return 'Validation failed';
    if (event.kind === 'patch.saved') return 'Patch saved after validation';
    return event.message || 'Validation updated';
  }
  if (key === 'review') {
    if (event.kind === 'review.finished') return 'Review verdict recorded';
    if (event.kind === 'review.failed') return 'Review failed';
    if (event.kind === 'review.invalid_output') return 'Review returned invalid output';
    return 'Review activity recorded';
  }
  if (event.kind === 'main.pushed') return `Pushed ${shortSha(event.message)}`;
  if (event.kind === 'integration.queued') return 'Integration queued';
  if (event.kind === 'integration.started') return 'Integration started';
  return 'Integration activity recorded';
}

function publicFallbackStageDetail(key: PublicTaskStageKey, complete: boolean) {
  if (key === 'plan') return complete ? 'Implementation plan recorded' : 'Waiting for plan';
  if (key === 'code') return complete ? 'Worker session captured' : 'Waiting for worker';
  if (key === 'validation') return complete ? 'Validation gates recorded' : 'No validation run yet';
  if (key === 'review') return complete ? 'Reviewer verdict recorded' : 'Waiting for review';
  return complete ? 'Integration activity recorded' : 'Waiting for integration';
}

function publicEventStage(event?: PublicStewardEvent): PublicTaskStageKey | null {
  const kind = event?.kind || '';
  const phase = typeof event?.data.phase === 'string' ? event.data.phase : '';
  if (kind.startsWith('implementation_plan.') || phase === 'implementation_plan') return 'plan';
  if (kind === 'task.status' && phase === 'validation') return 'validation';
  if (kind.startsWith('worker.') || kind === 'worker.finished' || kind === 'worktree.ready') return 'code';
  if (kind.startsWith('validation.') || kind === 'patch.saved') return 'validation';
  if (kind.startsWith('review.')) return 'review';
  if (kind.startsWith('integration.') || kind === 'main.pushed') return 'integration';
  return null;
}

function stageIcon(state: PublicTaskStageState) {
  if (state === 'complete') return <CheckCircle2 size={15} />;
  if (state === 'blocked') return <XCircle size={15} />;
  if (state === 'active') return <span className="live-spinner" aria-hidden="true" />;
  return <Circle size={12} />;
}

function Spinner() {
  return <span className="live-spinner" aria-hidden="true" />;
}

export function defaultAttemptTab(stage: PublicTaskStageKey): 'transcript' | 'patch' | 'validation' | 'review' {
  if (stage === 'validation') return 'validation';
  if (stage === 'review') return 'review';
  if (stage === 'integration') return 'patch';
  return 'transcript';
}

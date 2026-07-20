"use client";

import {
  BaseEdge,
  EdgeLabelRenderer,
  Handle,
  MarkerType,
  Position,
  ReactFlow,
  getSmoothStepPath,
  type Edge,
  type EdgeProps,
  type Node,
  type NodeProps,
} from "@xyflow/react";
import { useMemo, useState } from "react";

export interface PipelineStage {
  id: string;
  label: string;
  state: string;
  detail: string;
}

export interface PipelineTransition extends Record<string, unknown> {
  from: string;
  to: string;
  count: number;
  label: string;
  attempts: number[];
  causes: Array<{ attempt: number | null; detail: string }>;
}

interface StageNodeData extends Record<string, unknown> {
  label: string;
  state: string;
  detail: string;
}

const positions: Record<string, { x: number; y: number }> = {
  plan: { x: 0, y: 42 },
  implementation: { x: 225, y: 42 },
  validation: { x: 450, y: 42 },
  review: { x: 675, y: 42 },
  integration: { x: 900, y: 42 },
};

function formatAttempts(attempts: number[]) {
  return attempts.map((attempt) => String(attempt + 1).padStart(2, "0")).join(", ");
}

function StageNode({ data }: NodeProps<Node<StageNodeData>>) {
  const border = data.state === "active" ? "border-accent" : data.state === "blocked" ? "border-negative" : data.state === "complete" ? "border-line-strong" : "border-line";
  return (
    <div className={`w-44 border bg-surface px-4 py-3 text-left ${border}`}>
      <Handle id="forward-in" type="target" position={Position.Left} className="!size-1 !border-0 !bg-transparent" />
      <Handle id="forward-out" type="source" position={Position.Right} className="!size-1 !border-0 !bg-transparent" />
      <Handle id="return-in" type="target" position={Position.Bottom} className="!size-1 !border-0 !bg-transparent" />
      <Handle id="return-out" type="source" position={Position.Bottom} className="!size-1 !border-0 !bg-transparent" />
      <p className="text-sm font-semibold text-ink">{data.label}</p>
      <p className="mt-1 truncate text-xs text-muted data-text">{data.detail}</p>
    </div>
  );
}

const nodeTypes = { stage: StageNode };

interface TransitionEdgeData extends Record<string, unknown> {
  transition: PipelineTransition;
  color: string;
  highlighted: boolean;
  offset: number;
  onSelect: () => void;
  onHover: (hovered: boolean) => void;
}

function TransitionEdge({ sourceX, sourceY, sourcePosition, targetX, targetY, targetPosition, markerEnd, data }: EdgeProps<Edge<TransitionEdgeData>>) {
  if (!data) return null;
  const [path, labelX, labelY] = getSmoothStepPath({
    sourceX,
    sourceY,
    sourcePosition,
    targetX,
    targetY,
    targetPosition,
    offset: data.offset,
    borderRadius: 0,
  });
  const { transition, color, highlighted } = data;
  const interactive = transition.count > 0;
  return <>
    <BaseEdge path={path} markerEnd={markerEnd} interactionWidth={24} style={{ stroke: color, strokeWidth: highlighted ? 2.5 : 1.5, strokeDasharray: interactive ? undefined : "4 5" }} />
    <EdgeLabelRenderer>
      <button
        type="button"
        aria-label={`${transition.label}: ${transition.count} transition${transition.count === 1 ? "" : "s"}`}
        aria-pressed={interactive ? highlighted : undefined}
        disabled={!interactive}
        className="nodrag nopan absolute border-0 bg-surface px-1.5 py-0.5 text-xs font-semibold data-text disabled:cursor-default"
        style={{ color, transform: `translate(-50%, -50%) translate(${labelX}px, ${labelY}px)`, pointerEvents: "all" }}
        onClick={data.onSelect}
        onMouseEnter={() => data.onHover(true)}
        onMouseLeave={() => data.onHover(false)}
      >
        {transition.count}
      </button>
    </EdgeLabelRenderer>
  </>;
}

const edgeTypes = { transition: TransitionEdge };

function transitionTone(transition: PipelineTransition) {
  if (transition.from === "validation" && transition.to === "implementation") return "var(--warning)";
  if (transition.from === "review" && transition.to === "implementation") return "var(--negative)";
  if (transition.from === "integration" && transition.to === "implementation") return "var(--negative)";
  if (transition.count > 0 && transition.to === "integration") return "var(--positive)";
  if (transition.count > 0) return "var(--line-strong)";
  return "var(--line)";
}

export function PipelineGraph({ stages, transitions }: { stages: PipelineStage[]; transitions: PipelineTransition[] }) {
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [hoveredId, setHoveredId] = useState<string | null>(null);
  const highlightedId = hoveredId ?? selectedId;
  const selected = transitions.find((transition) => `${transition.from}-${transition.to}` === highlightedId) ?? null;
  const nodes = useMemo<Node<StageNodeData>[]>(() => stages.map((stage) => ({
    id: stage.id,
    type: "stage",
    position: positions[stage.id],
    data: { label: stage.label, state: stage.state, detail: stage.detail },
    draggable: false,
    selectable: false,
  })), [stages]);
  const edges = useMemo<Edge[]>(() => transitions.map((transition) => {
    const id = `${transition.from}-${transition.to}`;
    const isReturn = transition.to === "implementation" && transition.from !== "plan";
    const color = transitionTone(transition);
    return {
      id,
      source: transition.from,
      target: transition.to,
      sourceHandle: isReturn ? "return-out" : "forward-out",
      targetHandle: isReturn ? "return-in" : "forward-in",
      type: "transition",
      focusable: false,
      selectable: false,
      markerEnd: { type: MarkerType.ArrowClosed, width: 14, height: 14, color },
      data: {
        transition,
        color,
        highlighted: highlightedId === id,
        offset: isReturn ? transition.from === "integration" ? 92 : transition.from === "review" ? 64 : 36 : 18,
        onSelect: () => transition.count > 0 && setSelectedId((current) => current === id ? null : id),
        onHover: (hovered: boolean) => transition.count > 0 && setHoveredId(hovered ? id : null),
      },
    };
  }), [highlightedId, transitions]);

  const completedTransitions = transitions.reduce((sum, transition) => sum + transition.count, 0);
  const returnTransitions = transitions.filter((transition) => transition.to === "implementation" && transition.from !== "plan").reduce((sum, transition) => sum + transition.count, 0);
  const returnedAttempts = new Set(transitions.flatMap((transition) => transition.to === "implementation" && transition.from !== "plan" ? transition.attempts : [])).size;

  return (
    <section aria-labelledby="pipeline-title" className="border-y border-line py-7 sm:py-8">
      <div className="flex flex-col gap-2 sm:flex-row sm:items-baseline sm:justify-between">
        <h2 id="pipeline-title" className="text-xl font-semibold text-ink">Execution pipeline</h2>
        <p className="text-xs text-muted data-text">{completedTransitions} transitions · {returnTransitions} returns</p>
      </div>

      <div className="mt-4 hidden md:block">
        <div className="h-[17rem]" aria-label="Task state transition graph">
          <ReactFlow
            nodes={nodes}
            edges={edges}
            nodeTypes={nodeTypes}
            edgeTypes={edgeTypes}
            fitView
            fitViewOptions={{ padding: 0.12, minZoom: 0.75, maxZoom: 1.05 }}
            minZoom={0.75}
            maxZoom={1.05}
            nodesDraggable={false}
            nodesConnectable={false}
            edgesReconnectable={false}
            elementsSelectable
            panOnDrag={false}
            zoomOnDoubleClick={false}
            zoomOnPinch={false}
            zoomOnScroll={false}
            preventScrolling={false}
            proOptions={{ hideAttribution: true }}
          />
        </div>
        <div className="min-h-20 border-t border-line pt-4" aria-label="Selected transition evidence" aria-live="polite">
          {selected ? (
            <div className="grid gap-2 sm:grid-cols-[13rem_minmax(0,1fr)] sm:gap-6">
              <div>
                <p className="text-sm font-semibold text-ink">{selected.label}</p>
                <p className="mt-1 text-xs text-muted data-text">Attempts {formatAttempts(selected.attempts)}</p>
              </div>
              <ul className="space-y-1 text-xs leading-5 text-muted">
                {selected.causes.map((cause, index) => <li key={`${cause.attempt}-${index}`}><span className="mr-2 text-faint data-text">{cause.attempt === null ? "Plan" : `A${String(cause.attempt + 1).padStart(2, "0")}`}</span><span>{cause.detail}</span></li>)}
              </ul>
            </div>
          ) : <p className="text-xs leading-5 text-muted">{returnTransitions ? `${returnTransitions} returns extended execution across ${returnedAttempts} attempts.` : "No return transitions recorded."}</p>}
        </div>
      </div>

      <ol className="mt-5 border-t border-line md:hidden" aria-label="Task state transitions">
        {transitions.map((transition) => (
          <li key={`${transition.from}-${transition.to}`} className="grid grid-cols-[minmax(0,1fr)_2.5rem] gap-3 border-b border-line py-3">
            <div><p className="text-sm font-medium text-ink">{transition.label}</p>{transition.attempts.length ? <p className="mt-1 text-xs text-muted data-text">Attempts {formatAttempts(transition.attempts)}</p> : null}</div>
            <span className="text-right text-sm font-semibold text-ink data-text">{transition.count}</span>
          </li>
        ))}
      </ol>
    </section>
  );
}

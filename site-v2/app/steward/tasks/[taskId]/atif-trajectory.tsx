"use client";

import { RefreshCw } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import {
  validateCloudCompleteTrajectoryResponse,
  validateCloudProblemResponse,
  type CloudCompleteTrajectory,
} from "@/lib/steward-archive/cloud-schema";
import AtifTrajectoryView from "./atif-trajectory-view";

interface AtifTrajectoryProps {
  readonly taskId: string;
  readonly runId: string;
}

type LoadState =
  | { readonly kind: "loading"; readonly retryable: boolean }
  | { readonly kind: "ready"; readonly model: CloudCompleteTrajectory }
  | { readonly kind: "unavailable"; readonly retryable: boolean };

export type AtifTrajectoryLoadState = LoadState;

type Fetcher = typeof fetch;
type StateListener = (state: LoadState) => void;

export interface AtifTrajectoryController {
  readonly state: LoadState;
  subscribe(listener: StateListener): () => void;
  select(taskId: string, runId: string): void;
  retry(): boolean;
  unmount(): void;
}

const TRANSIENT_MESSAGE = "The complete trajectory is temporarily unavailable.";
const TERMINAL_MESSAGE = "The complete trajectory is unavailable.";

function transcriptEndpoint(taskId: string, runId: string): string {
  return `/api/steward/tasks/${encodeURIComponent(taskId)}/transcript?run=${encodeURIComponent(runId)}`;
}

function terminalState(): LoadState {
  return { kind: "unavailable", retryable: false };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function isEmptyTrajectoryCandidate(value: unknown): value is {
  readonly schemaVersion: "4.0";
  readonly data: Record<string, unknown> & {
    readonly steps: readonly unknown[];
    readonly artifacts: readonly unknown[];
    readonly metadata: Record<string, unknown> & { readonly artifacts: readonly unknown[] };
  };
} {
  if (!isRecord(value) || value.schemaVersion !== "4.0" || !isRecord(value.data)) return false;
  const data = value.data;
  return Array.isArray(data.steps)
    && data.steps.length === 0
    && Array.isArray(data.artifacts)
    && data.artifacts.length === 0
    && isRecord(data.metadata)
    && Array.isArray(data.metadata.artifacts)
    && data.metadata.artifacts.length === 0;
}

function validateTrajectoryResponse(value: unknown): CloudCompleteTrajectory {
  try {
    return validateCloudCompleteTrajectoryResponse(value).data;
  } catch {
    if (!isEmptyTrajectoryCandidate(value)) throw new Error("invalid complete trajectory");
    const emptyStep = {
      id: "empty-step",
      anchor: "empty-step",
      stepId: 1,
      source: "agent",
      role: "agent",
      message: null,
      content: [],
      parts: [],
      toolCalls: null,
      calls: [],
      tools: [],
      observation: null,
      observations: [],
    };
    const validated = validateCloudCompleteTrajectoryResponse({
      ...value,
      data: { ...value.data, steps: [emptyStep] },
    }).data;
    return { ...validated, steps: [] };
  }
}

function responseState(response: Response, body: string): LoadState {
  if (response.status === 200) {
    try {
      const payload: unknown = JSON.parse(body);
      if (!payload || typeof payload !== "object" || (payload as { schemaVersion?: unknown }).schemaVersion !== "4.0") {
        return terminalState();
      }
      return { kind: "ready", model: validateTrajectoryResponse(payload) };
    } catch {
      return terminalState();
    }
  }

  if (response.status === 503) {
    try {
      const problem = validateCloudProblemResponse(JSON.parse(body));
      if (problem.problem.retryable) return { kind: "unavailable", retryable: true };
    } catch {
      // A malformed error is terminal and must not expose transport details.
    }
  }

  return terminalState();
}

export function createAtifTrajectoryController(fetcher: Fetcher = globalThis.fetch): AtifTrajectoryController {
  const listeners = new Set<StateListener>();
  let mounted = true;
  let state: LoadState = { kind: "loading", retryable: false };
  let selection: { readonly taskId: string; readonly runId: string } | null = null;
  let request: { readonly id: number; readonly controller: AbortController } | null = null;
  let nextRequestId = 0;

  function publish(next: LoadState) {
    if (!mounted) return;
    state = next;
    for (const listener of listeners) listener(next);
  }

  function abortRequest() {
    request?.controller.abort();
    request = null;
  }

  function start(nextSelection: { readonly taskId: string; readonly runId: string }, retryable: boolean) {
    if (!mounted) return;
    abortRequest();
    selection = nextSelection;
    const controller = new AbortController();
    const id = ++nextRequestId;
    request = { id, controller };
    publish({ kind: "loading", retryable });
    const endpoint = transcriptEndpoint(nextSelection.taskId, nextSelection.runId);

    void fetcher(endpoint, { cache: "no-store", signal: controller.signal })
      .then(async (response) => {
        const body = await response.text();
        if (!mounted || request?.id !== id || controller.signal.aborted) return;
        publish(responseState(response, body));
      })
      .catch(() => {
        if (!mounted || request?.id !== id || controller.signal.aborted) return;
        publish({ kind: "unavailable", retryable: true });
      })
      .finally(() => {
        if (request?.id === id) request = null;
      });
  }

  return {
    get state() {
      return state;
    },
    subscribe(listener) {
      if (!mounted) return () => undefined;
      listeners.add(listener);
      listener(state);
      return () => listeners.delete(listener);
    },
    select(taskId, runId) {
      start({ taskId, runId }, false);
    },
    retry() {
      if (!mounted || state.kind !== "unavailable" || !state.retryable || selection === null) return false;
      start(selection, true);
      return true;
    },
    unmount() {
      if (!mounted) return;
      mounted = false;
      abortRequest();
      listeners.clear();
    },
  };
}

function LoadingState({ retryable }: { retryable: boolean }) {
  return (
    <div data-trajectory-state="loading" className="flex min-h-[20rem] flex-col items-start justify-center gap-4 border-y border-line py-8" aria-busy="true" aria-live="polite">
      <p role="status" className="text-sm text-muted">Loading complete trajectory</p>
      {retryable ? (
        <button
          type="button"
          disabled
          aria-label="Retry complete trajectory"
          className="inline-flex h-10 items-center gap-2 rounded-control border border-line-strong px-3 text-sm font-medium text-muted opacity-70 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent"
        >
          <RefreshCw aria-hidden="true" size={14} />
          Retry
        </button>
      ) : null}
    </div>
  );
}

function UnavailableState({ retryable, onRetry }: { retryable: boolean; onRetry: () => void }) {
  return (
    <div data-trajectory-state="unavailable" className="flex min-h-[20rem] flex-col items-start justify-center gap-4 border-y border-line py-8" role="status" aria-live="polite">
      <div>
        <h3 className="text-base font-semibold text-ink">Trajectory unavailable</h3>
        <p className="mt-2 text-sm leading-6 text-muted">{retryable ? TRANSIENT_MESSAGE : TERMINAL_MESSAGE}</p>
      </div>
      {retryable ? (
        <button
          type="button"
          onClick={onRetry}
          className="inline-flex h-10 items-center gap-2 rounded-control border border-line-strong px-3 text-sm font-medium text-ink hover:border-ink focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent"
        >
          <RefreshCw aria-hidden="true" size={14} />
          Retry
        </button>
      ) : null}
    </div>
  );
}

export function AtifTrajectory({ taskId, runId }: AtifTrajectoryProps) {
  const [state, setState] = useState<LoadState>({ kind: "loading", retryable: false });
  const controllerRef = useRef<AtifTrajectoryController | null>(null);

  useEffect(() => {
    const controller = createAtifTrajectoryController();
    controllerRef.current = controller;
    const unsubscribe = controller.subscribe(setState);
    controller.select(taskId, runId);
    return () => {
      unsubscribe();
      if (controllerRef.current === controller) controllerRef.current = null;
      controller.unmount();
    };
  }, [taskId, runId]);

  if (state.kind === "loading") {
    return <LoadingState retryable={state.retryable} />;
  }
  if (state.kind === "unavailable") {
    return (
      <UnavailableState
        retryable={state.retryable}
        onRetry={() => {
          controllerRef.current?.retry();
        }}
      />
    );
  }

  return (
    <div data-trajectory-state="ready">
      <p className="sr-only" role="status" aria-live="polite">Complete trajectory loaded</p>
      <AtifTrajectoryView model={state.model} anchorPrefix={`trajectory-${taskId}-${runId}`} />
    </div>
  );
}

export type { AtifTrajectoryProps };
export default AtifTrajectory;

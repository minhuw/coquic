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

const TRANSIENT_MESSAGE = "The complete trajectory is temporarily unavailable.";
const TERMINAL_MESSAGE = "The complete trajectory is unavailable.";

function transcriptEndpoint(taskId: string, runId: string): string {
  return `/api/steward/tasks/${encodeURIComponent(taskId)}/transcript?run=${encodeURIComponent(runId)}`;
}

function terminalState(): LoadState {
  return { kind: "unavailable", retryable: false };
}

function responseState(response: Response, body: string): LoadState {
  if (response.status === 200) {
    try {
      const payload: unknown = JSON.parse(body);
      if (!payload || typeof payload !== "object" || (payload as { schemaVersion?: unknown }).schemaVersion !== "4.0") {
        return terminalState();
      }
      return { kind: "ready", model: validateCloudCompleteTrajectoryResponse(payload).data };
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
  const endpoint = transcriptEndpoint(taskId, runId);
  const [attempt, setAttempt] = useState(0);
  const [state, setState] = useState<LoadState>({ kind: "loading", retryable: false });
  const retrying = useRef(false);

  useEffect(() => {
    let active = true;
    const controller = new AbortController();
    const showRetry = retrying.current;
    retrying.current = false;
    setState({ kind: "loading", retryable: showRetry });

    async function load() {
      try {
        const response = await fetch(endpoint, { cache: "no-store", signal: controller.signal });
        const body = await response.text();
        if (!active || controller.signal.aborted) return;
        setState(responseState(response, body));
      } catch {
        if (!active || controller.signal.aborted) return;
        setState({ kind: "unavailable", retryable: true });
      }
    }

    void load();
    return () => {
      active = false;
      controller.abort();
    };
  }, [endpoint, attempt]);

  if (state.kind === "loading") {
    return <LoadingState retryable={state.retryable} />;
  }
  if (state.kind === "unavailable") {
    return (
      <UnavailableState
        retryable={state.retryable}
        onRetry={() => {
          retrying.current = true;
          setState({ kind: "loading", retryable: true });
          setAttempt((value) => value + 1);
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

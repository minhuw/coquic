"use client";

import Link from "next/link";
import {
  Activity,
  CheckCircle2,
  ExternalLink,
  FileText,
  GitBranch,
  ListChecks,
  RefreshCw,
  XCircle,
} from "lucide-react";
import { type ReactNode, useCallback, useEffect, useState } from "react";
import { getIntegration, getTaskFile, getValidationLog } from "./api";
import { TimelineEvent } from "./timeline";
import type { IntegrationDetail, TaskStatus, ValidationResult } from "./types";

type IntegrationStageKey = "queued" | "apply" | "validate" | "commit" | "push";
type IntegrationStageState = "pending" | "active" | "complete" | "blocked";

type IntegrationStage = {
  key: IntegrationStageKey;
  label: string;
  state: IntegrationStageState;
  detail: string;
};

type LoadedIntegration = {
  detail: IntegrationDetail;
  patch: string;
  transcript: string;
};

export function IntegrationDetailRoute({ integrationId }: { integrationId: string }) {
  const [loaded, setLoaded] = useState<LoadedIntegration | null>(null);
  const [loadError, setLoadError] = useState("");
  const [validationLog, setValidationLog] = useState<{ index: number; text: string } | null>(null);
  const [streamState, setStreamState] = useState("connecting");

  const loadIntegration = useCallback(async () => {
    const detail = await getIntegration(integrationId);
    let patch = await getTaskFile(integrationId, "patch");
    if (!patch && detail.run.source_task_id) {
      patch = await getTaskFile(detail.run.source_task_id, "patch");
    }
    const transcript = detail.run.transcript_path
      ? await getTaskFile(integrationId, "transcript")
      : "";
    setLoaded({ detail, patch, transcript });
    setLoadError("");
  }, [integrationId]);

  const refreshIntegration = useCallback(async () => {
    try {
      await loadIntegration();
    } catch (error) {
      setLoadError(errorMessage(error, "Unable to load integration run."));
      setStreamState("reconnecting");
    }
  }, [loadIntegration]);

  useEffect(() => {
    const timer = window.setTimeout(() => void refreshIntegration(), 0);
    return () => window.clearTimeout(timer);
  }, [refreshIntegration]);

  useEffect(() => {
    const source = new EventSource("/api/stream");
    source.addEventListener("open", () => setStreamState("live"));
    source.addEventListener("error", () => setStreamState("reconnecting"));
    source.addEventListener("state", () => void refreshIntegration());
    return () => source.close();
  }, [refreshIntegration]);

  async function showValidation(index: number) {
    try {
      setValidationLog({ index, text: await getValidationLog(integrationId, index) });
    } catch (error) {
      setLoadError(errorMessage(error, "Unable to load validation log."));
    }
  }

  if (!loaded) {
    return (
      <main className="task-page-frame">
        <section className="task-page-shell">
          <div className="empty-state">
            {loadError || "Loading integration run."}
            {loadError && (
              <button className="button-inline" onClick={() => void refreshIntegration()} type="button">
                Retry
              </button>
            )}
          </div>
        </section>
      </main>
    );
  }

  const { detail, patch, transcript } = loaded;
  const run = detail.run;
  const stages = integrationStages(detail);
  const timelineEvents = [...detail.events, ...detail.source_events]
    .sort((left, right) => left.created_at.localeCompare(right.created_at))
    .reverse();

  return (
    <main className="task-page-frame">
      <section className="task-page-shell">
        <header className="task-page-topbar">
          <Link className="task-back-link" href="/">Back to dashboard</Link>
          <div className="top-actions">
            <span className={`stream-pill ${streamState}`}>{streamState}</span>
            <button className="icon-button secondary" onClick={() => void refreshIntegration()} type="button" title="Refresh integration">
              <RefreshCw size={16} />
            </button>
          </div>
        </header>

        {loadError && <div className="inline-alert">{loadError}</div>}

        <section className="panel task-overview-card" aria-label="Integration overview">
          <PanelTitle icon={<GitBranch size={17} />} title="Integration Run" />
          <div className="task-overview-head">
            <div className="task-title-row">
              <h1>{run.source_title || run.title}</h1>
              <StatusPill status={run.status} />
            </div>
            <p>{run.summary || "Steward is applying, validating, committing, or pushing the reviewed patch."}</p>
            <div className="task-overview-meta" aria-label="Integration facts">
              <b>serialized main lane</b>
              <span>{integrationStageSummary(detail)}</span>
              {run.source_task_id && <Link className="commit-link" href={taskHref(run.source_task_id)}>Source task</Link>}
              {detail.remote.commit && detail.remote.commit_url && (
                <GithubCommitLink commit={detail.remote.commit} url={detail.remote.commit_url} />
              )}
            </div>
          </div>
        </section>

        <div className="task-detail-layout">
          <main className="task-detail-main">
            <section className="panel integration-run-panel">
              <PanelTitle icon={<GitBranch size={17} />} title="Integration Pipeline" />
              <div className="integration-stage-row">
                {stages.map((stage) => (
                  <article className={`integration-stage-card ${stage.state}`} key={stage.key}>
                    <span className="pipeline-node-dot">{stage.state === "complete" ? <CheckCircle2 size={15} /> : stage.state === "blocked" ? <XCircle size={15} /> : <Activity size={14} />}</span>
                    <div>
                      <b>{stage.label}</b>
                      <p>{stage.detail}</p>
                    </div>
                  </article>
                ))}
              </div>
            </section>

            <section className="panel">
              <PanelTitle icon={<FileText size={17} />} title="Integration Transcript" />
              {transcript ? (
                <pre className="integration-transcript code-pane compact">{transcript}</pre>
              ) : (
                <div className="empty-state">No integration transcript has been captured yet.</div>
              )}
            </section>

            <section className="panel">
              <PanelTitle icon={<ListChecks size={17} />} title="Validation" />
              <IntegrationValidations
                log={validationLog?.text || ""}
                logIndex={validationLog?.index ?? null}
                onShow={showValidation}
                validations={detail.validations}
              />
            </section>

            <section className="panel">
              <PanelTitle icon={<FileText size={17} />} title="Patch" />
              {patch ? <DiffView text={patch} /> : <div className="empty-state">No integration patch artifact is available.</div>}
            </section>
          </main>

          <aside className="task-detail-aside">
            <section className="panel task-timeline-panel">
              <PanelTitle icon={<ListChecks size={17} />} title="Integration Timeline" />
              <ol className="timeline compact">
                {timelineEvents.map((event) => <TimelineEvent event={event} key={`${event.task_id}-${event.created_at}-${event.kind}`} />)}
                {!timelineEvents.length && <li className="muted">No integration events recorded.</li>}
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

function IntegrationValidations({
  log,
  logIndex,
  onShow,
  validations,
}: {
  log: string;
  logIndex: number | null;
  onShow: (index: number) => void;
  validations: Array<ValidationResult & { index: number }>;
}) {
  if (!validations.length) return <div className="empty-state">No integration validation has run yet.</div>;
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
      {log && validations.some((validation) => validation.index === logIndex) && <pre className="code-pane compact">{log}</pre>}
    </div>
  );
}

function integrationStages(detail: IntegrationDetail): IntegrationStage[] {
  const events = [...detail.events, ...detail.source_events];
  const hasSource = events.some((event) => event.kind === "integration.source" || event.kind === "integration.started");
  const hasValidation = detail.validations.length > 0;
  const hasCommit = Boolean(detail.remote.commit) || events.some((event) => event.kind === "integration.local_only" || event.kind === "integration.push_failed");
  const hasPush = Boolean(detail.remote.commit) || events.some((event) => event.kind === "main.pushed");
  const blocked = ["blocked", "failed", "cancelled"].includes(detail.run.status);
  const active = activeIntegrationStage(detail, { hasSource, hasValidation, hasCommit, hasPush });
  return [
    integrationStage("queued", "Queued", "Waiting for the serialized integration lane", true, active, blocked),
    integrationStage("apply", "Apply Patch", "Apply reviewed patch on latest main", hasSource, active, blocked),
    integrationStage("validate", "Validate", "Run gates after applying the patch", hasValidation, active, blocked),
    integrationStage("commit", "Commit", "Create the integration commit", hasCommit, active, blocked),
    integrationStage("push", "Push", "Push the resulting commit to main", hasPush, active, blocked),
  ];
}

function activeIntegrationStage(
  detail: IntegrationDetail,
  state: { hasSource: boolean; hasValidation: boolean; hasCommit: boolean; hasPush: boolean },
): IntegrationStageKey {
  if (detail.run.status === "pushed" || state.hasPush) return "push";
  if (detail.run.status === "succeeded" || state.hasCommit) return "commit";
  if (detail.run.status === "queued") return "queued";
  if (!state.hasSource) return "apply";
  if (!state.hasValidation) return "validate";
  if (!state.hasCommit) return "commit";
  return "push";
}

function integrationStage(
  key: IntegrationStageKey,
  label: string,
  detail: string,
  complete: boolean,
  active: IntegrationStageKey,
  blocked: boolean,
): IntegrationStage {
  return {
    key,
    label,
    detail,
    state: blocked && key === active ? "blocked" : key === active && !complete ? "active" : complete ? "complete" : "pending",
  };
}

function integrationStageSummary(detail: IntegrationDetail) {
  const stages = integrationStages(detail);
  const active = stages.find((stage) => stage.state === "active" || stage.state === "blocked")
    ?? lastCompleteStage(stages)
    ?? stages[0];
  return active ? active.label : "Integration";
}

function lastCompleteStage(stages: IntegrationStage[]) {
  for (let index = stages.length - 1; index >= 0; index -= 1) {
    if (stages[index].state === "complete") return stages[index];
  }
  return null;
}

function DiffView({ text }: { text: string }) {
  return (
    <pre className="code-pane">
      {text.split("\n").map((line, index) => (
        <Line line={line} key={index} />
      ))}
    </pre>
  );
}

function Line({ line }: { line: string }) {
  let className = "diff-line";
  if (line.startsWith("+")) className += " added";
  if (line.startsWith("-")) className += " removed";
  if (line.startsWith("@@")) className += " hunk";
  return <span className={className}>{line}{"\n"}</span>;
}

function StatusPill({ status }: { status: string | TaskStatus }) {
  return <span className={`status status-${status}`}>{status}</span>;
}

function GithubCommitLink({ commit, url }: { commit: string; url: string }) {
  return (
    <a className="commit-link" href={url} rel="noreferrer" target="_blank">
      <ExternalLink size={14} />
      <span className="mono">{shortSha(commit)}</span>
    </a>
  );
}

function taskHref(taskId: string) {
  return `/tasks/${encodeURIComponent(taskId)}`;
}

function shortSha(value: string) {
  return value.slice(0, 12);
}

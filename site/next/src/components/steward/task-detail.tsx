'use client';

import Link from 'next/link';
import {
  Activity,
  AlertTriangle,
  ArrowLeft,
  CheckCircle2,
  ChevronRight,
  Circle,
  Clock3,
  ExternalLink,
  FileText,
  GitBranch,
  ListChecks,
  XCircle,
} from 'lucide-react';
import { type ReactNode, useEffect, useState } from 'react';

import { CodeBlock } from '@/components/steward-code-block';
import { TranscriptView } from '@/components/steward-transcript';
import type { PublicCodexRunDiagnostics } from '@/components/steward-transcript';

import { usePublicStewardState, usePublicStewardTaskDetail, type StewardRequestStatus } from './data';
import {
  handleTabKeyDown,
  relativeTime,
  shortDate,
  shortSha,
  StewardStatusLabel,
  stewardStatusTone,
} from './shared';
import { defaultAttemptTab, publicTaskFlow, TaskFlowPanel } from './task-flow';
import type {
  PublicAttemptTab,
  PublicReviewFinding,
  PublicReviewRecord,
  PublicReviewShape,
  PublicStewardArtifact,
  PublicStewardAttempt,
  PublicStewardEvent,
  PublicStewardPlanRun,
  PublicStewardTaskDetail,
  PublicTaskStageKey,
  PublicTimelineChip,
  PublicTimelineField,
  PublicTimelineModel,
  PublicTimelineTone,
} from './types';

export function StewardTaskDetailLive({ taskId }: { taskId: string }) {
  const monitor = usePublicStewardState();
  const task = monitor.state?.tasks.find((item) => item.id === taskId) ?? null;
  const detailState = usePublicStewardTaskDetail(taskId, task?.detail_json);
  return (
    <StewardTaskDetail
      detail={detailState.detail}
      loaded={detailState.loaded}
      requestStatus={detailState.result.status}
      taskId={taskId}
    />
  );
}

export function StewardTaskDetail({
  detail,
  loaded,
  requestStatus,
  taskId,
}: {
  detail: PublicStewardTaskDetail | null;
  loaded: boolean;
  requestStatus?: StewardRequestStatus;
  taskId: string;
}) {
  if (!detail) {
    return (
      <TaskPageState loaded={loaded} requestStatus={requestStatus} taskId={taskId} />
    );
  }
  const task = detail.task;
  const flow = publicTaskFlow(detail);
  const latestAttemptNumber = detail.attempts.at(-1)?.attempt ?? null;
  const timelineEvents = [...detail.events].reverse();
  const featureWorkflow = isFeatureWorkflow(task);
  const currentStage = flow.stages.find((stage) => stage.key === flow.activeKey);
  const blockedStage = flow.stages.find((stage) => stage.state === 'blocked');
  return (
    <TaskSurface>
      <section className="task-page-shell">
        <header className="task-page-topbar">
          <Link className="task-back-link" href="/steward">
            <ArrowLeft className="size-4" />
            Back to Steward
          </Link>
          <span className="task-snapshot font-mono">snapshot {relativeTime(detail.generated_at)}</span>
        </header>

        {requestStatus && requestStatus !== 'ready' && requestStatus !== 'loading' && (
          <div className={`task-refresh-note ${requestStatus}`} role="status">
            <AlertTriangle size={16} aria-hidden="true" />
            <span>Showing the last published task detail; the latest refresh is {requestStatus.replace('-', ' ')}.</span>
          </div>
        )}

        <header className="task-page-header">
          <div className="task-page-header-main">
            <span className="task-section-kicker">Steward task evidence</span>
            <div className="task-title-row">
              <h1>{task.title}</h1>
              <TaskStatus status={task.status} />
            </div>
            <p className="task-summary">{task.summary || `${task.kind} / ${task.worker}`}</p>
          </div>
          <div className={`task-conclusion ${blockedStage ? 'blocked' : ''}`}>
            <span className="task-conclusion-label">Current conclusion</span>
            <strong>{blockedStage ? `${task.status} at ${blockedStage.label}` : currentStage?.label ?? task.status}</strong>
            <span>{blockedStage ? blockedStage.detail : currentStage?.detail ?? 'No stage activity recorded yet.'}</span>
          </div>
        </header>

        <dl className="task-facts" aria-label="Task facts">
          <Fact label="Task ID" value={<code>{task.id}</code>} />
          <Fact label="Kind" value={task.kind} />
          <Fact label="Workflow" value={task.workflow || task.spec.workflow || (task.kind === 'feature' ? 'feature' : 'fix')} />
          <Fact label="Worker" value={task.worker || '-'} />
          <Fact label="Priority" value={task.priority || '-'} />
          <Fact label="Risk" value={task.risk || '-'} />
          <Fact label="Updated" value={<time dateTime={task.updated_at}>{shortDate(task.updated_at)}</time>} />
          <Fact label="Attempts" value={String(detail.attempts.length)} />
          <Fact label="Validations" value={String(detail.validations.length)} />
          <Fact label="Branch" value={<code className="task-breakable">{task.branch_name || '-'}</code>} />
          <Fact
            label="Commit"
            value={detail.remote.commit && detail.remote.commit_url ? (
              <a className="task-inline-link" href={detail.remote.commit_url} rel="noreferrer" target="_blank">
                <GitBranch size={15} aria-hidden="true" />
                <code>{shortSha(detail.remote.commit)}</code>
                <ExternalLink size={13} aria-hidden="true" />
              </a>
            ) : <code>{detail.remote.commit ? shortSha(detail.remote.commit) : 'Not published'}</code>}
          />
        </dl>

        <div className="task-detail-layout">
          <div className="task-detail-main">
            <TaskFlowPanel flow={flow} />
            {featureWorkflow && (
              <PublicPlanRuns planRuns={detail.plan_runs ?? []} />
            )}
            <section className="task-section attempts-section" aria-labelledby="attempts-heading">
              <header className="task-section-heading">
                <div>
                  <span className="task-section-kicker">Revision loop</span>
                  <h2 id="attempts-heading">Attempts</h2>
                </div>
                <span className="task-section-count">{detail.attempts.length} recorded</span>
              </header>
            <div className="attempt-stack page-stack">
              {detail.attempts.length ? (
                [...detail.attempts].reverse().map((attempt) => (
                  <AttemptCard
                    activeStage={flow.activeKey}
                    attempt={attempt}
                    isActiveAttempt={attempt.attempt === latestAttemptNumber}
                    key={`${attempt.attempt}-${attempt.label}`}
                    taskPrompt={task.spec.prompt || ''}
                  />
                ))
              ) : (
                <div className="empty-state compact">No worker, validation, or reviewer run has been captured yet.</div>
              )}
            </div>
            </section>

            {detail.integration.runs.length > 0 && <IntegrationDetailRuns runs={detail.integration.runs} />}

            <TaskTimeline events={timelineEvents} />
          </div>

          <aside className="task-detail-aside">
            <section className="task-context-panel" aria-labelledby="task-context-heading">
              <header className="task-section-heading compact">
                <div>
                  <span className="task-section-kicker">At a glance</span>
                  <h2 id="task-context-heading">Task context</h2>
                </div>
              </header>
              <dl className="task-context-facts">
                <Fact label="Published" value={<time dateTime={detail.generated_at}>{shortDate(detail.generated_at)}</time>} />
                <Fact label="Schema" value={String(detail.schema_version)} />
                <Fact label="Source" value={<code className="task-breakable">{task.source || '-'}</code>} />
                <Fact label="Events" value={String(detail.events.length)} />
                <Fact label="Artifacts" value={String(countArtifacts(detail))} />
              </dl>
            </section>
            {task.spec.prompt && (
              <details className="task-prompt">
                <summary>Task prompt</summary>
                <p>{task.spec.prompt}</p>
              </details>
            )}
          </aside>
        </div>
      </section>
    </TaskSurface>
  );
}

function TaskPageState({ loaded, requestStatus, taskId }: { loaded: boolean; requestStatus?: StewardRequestStatus; taskId: string }) {
  const state = requestStatus ?? (loaded ? 'not-published' : 'loading');
  const title = state === 'loading'
    ? 'Loading task detail'
    : state === 'not-published'
      ? 'Task detail is not published'
      : state === 'incompatible'
        ? 'Task detail schema is incompatible'
        : state === 'invalid'
          ? 'Task detail is invalid'
          : 'Task detail is unavailable';
  const message = state === 'loading'
    ? 'Loading task detail.'
    : state === 'not-published'
      ? <>Public detail for <span className="font-mono">{taskId}</span> has not been published yet.</>
      : state === 'incompatible'
        ? 'The published task detail cannot be read by this monitor.'
        : state === 'invalid'
          ? 'The published task detail did not match the expected JSON shape.'
          : 'The public Steward mirror could not be reached. Try again after the next publication.';
  return (
    <TaskSurface>
      <section className="task-page-shell">
        <header className="task-page-topbar">
          <Link className="task-back-link" href="/steward">
            <ArrowLeft className="size-4" />
            Back to Steward
          </Link>
        </header>
        <section className={`task-state task-state-${state}`} aria-live="polite">
          <span className="task-state-icon" aria-hidden="true">
            {state === 'loading' ? <Clock3 size={22} /> : state === 'not-published' ? <Circle size={22} /> : <AlertTriangle size={22} />}
          </span>
          <span className="task-section-kicker">Public task evidence</span>
          <h1>{title}</h1>
          <p>{message}</p>
          {state !== 'loading' && <code>{taskId}</code>}
        </section>
      </section>
    </TaskSurface>
  );
}

function TaskSurface({ children }: { children: ReactNode }) {
  return (
    <div className="steward-task-root" data-steward-module="task" data-steward-root="task">
      <div className="steward-public-page steward-task-style-scope">
        <div className="task-page-frame">
          {children}
        </div>
      </div>
    </div>
  );
}

function Fact({ label, value }: { label: string; value: ReactNode }) {
  return (
    <div>
      <dt>{label}</dt>
      <dd>{value}</dd>
    </div>
  );
}

function TaskStatus({ status }: { status: string }) {
  const tone = stewardStatusTone(status);
  return <StewardStatusLabel className={`task-status task-status-${tone}`} status={status} />;
}

function TaskTimeline({ events }: { events: PublicStewardEvent[] }) {
  return (
    <section className="task-section task-timeline-panel" aria-labelledby="timeline-heading">
      <header className="task-section-heading">
        <div>
          <span className="task-section-kicker">Event history</span>
          <h2 id="timeline-heading">Timeline</h2>
        </div>
        <span className="task-section-count">Newest first</span>
      </header>
      <ol className="timeline compact task-timeline" aria-label="Task timeline, newest first" tabIndex={0}>
        {events.map((event, index) => (
          <PublicTimelineEvent event={event} index={index} key={`${event.kind}-${event.created_at}-${index}`} />
        ))}
        {!events.length && <li className="muted">No events recorded</li>}
      </ol>
    </section>
  );
}

function isFeatureWorkflow(task: PublicStewardTaskDetail['task']) {
  return task.workflow === 'feature' || task.spec.workflow === 'feature' || task.kind === 'feature';
}

function countArtifacts(detail: PublicStewardTaskDetail) {
  const attemptArtifacts = detail.attempts.reduce((count, attempt) => count + Number(Boolean(attempt.patch || attempt.worker?.transcript || attempt.worker?.last_message || attempt.reviewer?.transcript || attempt.reviewer?.last_message)), 0);
  return attemptArtifacts + Number(Boolean(detail.artifacts.patch || detail.artifacts.transcript || detail.artifacts.last_message));
}

function IntegrationDetailRuns({
  runs,
}: {
  runs: PublicStewardTaskDetail['integration']['runs'];
}) {
  return (
    <section className="task-section steward-integration-detail-panel" aria-labelledby="integration-heading">
      <header className="task-section-heading">
        <div>
          <span className="task-section-kicker">Main branch evidence</span>
          <h2 id="integration-heading">Integration runs</h2>
        </div>
        <span className="task-section-count">{runs.length} recorded</span>
      </header>
      <div className="steward-integration-runs">
        {runs.map((run) => (
          <article className="steward-integration-run" key={run.task.id}>
            <div className="steward-integration-run-head">
              <div>
                <h3>{run.task.title}</h3>
                <span className="mono">{run.task.status} / {shortDate(run.task.updated_at)}</span>
              </div>
              {run.remote.commit && run.remote.commit_url && (
                <a className="steward-commit-link" href={run.remote.commit_url} rel="noreferrer" target="_blank">
                  <GitBranch className="size-4" />
                  <span>{shortSha(run.remote.commit)}</span>
                </a>
              )}
            </div>
            <div className="steward-integration-artifacts">
              <ArtifactContent
                artifact={run.commit_message?.last_message ?? run.commit_message?.transcript ?? null}
                empty="No commit-message artifact was published"
              >{(text) => <CodeBlock compact text={text} title="Commit message" />}</ArtifactContent>
              <ArtifactContent artifact={run.push_log} empty="No push log was published">
                {(text) => <CodeBlock compact text={text} title="Push log" />}
              </ArtifactContent>
            </div>
          </article>
        ))}
      </div>
    </section>
  );
}

function PublicPlanRuns({ planRuns }: { planRuns: PublicStewardPlanRun[] }) {
  return (
    <section className="task-section plan-runs-section" aria-labelledby="plan-runs-heading">
      <header className="task-section-heading">
        <div>
          <span className="task-section-kicker">Feature workflow</span>
          <h2 id="plan-runs-heading">Implementation plan</h2>
        </div>
        <span className="task-section-count">{planRuns.length} recorded</span>
      </header>
      {!planRuns.length && <div className="empty-state compact">No implementation plan run has been published yet.</div>}
      {[...planRuns].reverse().map((planRun) => (
        <article className="attempt-card" key={planRun.run}>
          <div className="attempt-card-head">
            <div>
              <h3>Plan run {planRun.run}</h3>
              <span className="font-mono text-xs">{planRun.name}</span>
            </div>
            <div className="attempt-card-meta plan-run-meta">
              <span>{planRun.model || 'default model'}</span>
              <span>{planRun.reasoning_effort || 'default reasoning'}</span>
              <TaskStatus status={planRun.completed && planRun.plan ? 'succeeded' : planRun.completed === false ? 'running' : 'failed'} />
            </div>
          </div>
          {planRun.plan ? (
            <CodeBlock language="json" text={JSON.stringify(planRun.plan, null, 2)} title="Structured plan" />
          ) : (
            <div className="empty-state compact">No valid structured plan was published.</div>
          )}
          <RunSection
            artifact={planRun.planner?.transcript ?? planRun.planner?.last_message ?? null}
            run={planRun.planner}
            title="Planner transcript"
          />
        </article>
      ))}
    </section>
  );
}

function AttemptCard({
  activeStage,
  attempt,
  isActiveAttempt,
  taskPrompt,
}: {
  activeStage: PublicTaskStageKey;
  attempt: PublicStewardAttempt;
  isActiveAttempt: boolean;
  taskPrompt: string;
}) {
  const stageTab = defaultAttemptTab(activeStage);
  const [open, setOpen] = useState(isActiveAttempt);
  const [userCollapsed, setUserCollapsed] = useState(false);
  const [selectedTab, setSelectedTab] = useState<PublicAttemptTab>('transcript');
  const [userSelectedTab, setUserSelectedTab] = useState(false);
  const visibleOpen = open || (isActiveAttempt && !userCollapsed);
  const active = isActiveAttempt && !userSelectedTab ? stageTab : selectedTab;
  const hasPatch = Boolean(attempt.patch?.text || attempt.patch?.url);
  const hasReview = Boolean(attempt.review || attempt.reviewer?.transcript?.text || attempt.reviewer?.last_message?.text || attempt.reviewer?.transcript?.url || attempt.reviewer?.last_message?.url);
  const tabs: Array<{ key: PublicAttemptTab; label: string; meta?: string | number }> = [
    { key: 'transcript', label: 'Transcript', meta: attempt.worker?.transcript || attempt.worker?.last_message ? 'captured' : undefined },
    { key: 'patch', label: 'Patch', meta: hasPatch ? 'saved' : undefined },
    { key: 'validation', label: 'Validation', meta: attempt.validations.length },
    { key: 'review', label: 'Review', meta: hasReview ? 'ready' : undefined },
  ];
  const attemptId = `steward-attempt-${attempt.attempt}`;
  return (
    <article className={`attempt-card ${isActiveAttempt ? 'active-run' : ''}`}>
      <button
        className="attempt-head"
        aria-expanded={visibleOpen}
        aria-controls={`${attemptId}-body`}
        onClick={() => {
          const nextOpen = !visibleOpen;
          setOpen(nextOpen);
          setUserCollapsed(!nextOpen);
        }}
        type="button"
      >
        <div className="attempt-title">
          <ChevronRight className="attempt-chevron" size={16} />
          <div>
            <span className="attempt-kicker mono">attempt {attempt.attempt}</span>
            <h3>{attempt.label}</h3>
          </div>
        </div>
        <div className="attempt-meta">
          <span>{attempt.worker ? 'worker' : 'no worker'}</span>
          <span>{attempt.validations.length} validations</span>
          <span>{attempt.reviewer ? 'reviewed' : 'not reviewed'}</span>
        </div>
      </button>
      {visibleOpen && (
        <div className="attempt-body" id={`${attemptId}-body`}>
          <div className="attempt-tabs" role="tablist" aria-label={`${attempt.label} run views`}>
            {tabs.map((tab) => (
              <button
                aria-controls={`${attemptId}-panel`}
                aria-selected={active === tab.key}
                className={active === tab.key ? 'active' : ''}
                id={`${attemptId}-tab-${tab.key}`}
                key={tab.key}
                onClick={() => {
                  setSelectedTab(tab.key);
                  setUserSelectedTab(true);
                }}
                onKeyDown={handleTabKeyDown}
                tabIndex={active === tab.key ? 0 : -1}
                role="tab"
                type="button"
              >
                <span>{tab.label}</span>
                {tab.meta !== undefined && <b>{tab.meta}</b>}
              </button>
            ))}
          </div>
          <div
            aria-labelledby={`${attemptId}-tab-${active}`}
            className="attempt-panel"
            id={`${attemptId}-panel`}
            role="tabpanel"
            tabIndex={0}
          >
            {active === 'transcript' && (
              <RunSection
                artifact={attempt.worker?.transcript ?? attempt.worker?.last_message ?? null}
                prompt={attempt.attempt === 0 ? taskPrompt : ''}
                run={attempt.worker}
                title="Worker transcript"
              />
            )}
            {active === 'patch' && <PatchSection artifact={attempt.patch} />}
            {active === 'validation' && <ValidationList validations={attempt.validations} />}
            {active === 'review' && <ReviewSection attempt={attempt} />}
          </div>
        </div>
      )}
    </article>
  );
}

function RunSection({
  artifact,
  prompt = '',
  run,
  title,
}: {
  artifact: PublicStewardArtifact;
  prompt?: string;
  run: NonNullable<PublicStewardAttempt['worker']> | PublicStewardPlanRun['planner'];
  title: string;
}) {
  return (
    <>
      <div className="attempt-section-head">
        <FileText size={15} />
        <h4>{title}</h4>
        {run?.name && <code>{run.name}</code>}
      </div>
      <ArtifactContent artifact={artifact} empty={`No ${title.toLowerCase()} published`}>
        {(text) => (
          <div className="attempt-transcript">
            <TranscriptView
              diagnostics={run?.diagnostics as PublicCodexRunDiagnostics | null | undefined}
              isLiveRun={false}
              prompt={prompt}
              taskId={run?.name || "public-steward-run"}
              text={text}
            />
          </div>
        )}
      </ArtifactContent>
    </>
  );
}

function PatchSection({ artifact }: { artifact: PublicStewardArtifact }) {
  return (
    <div className="run-patch">
      <ArtifactContent artifact={artifact} empty="No saved patch for this iteration">
        {(text) => <CodeBlock diffDisplay="unified-with-split-modal" language="diff" text={text} title="Patch" />}
      </ArtifactContent>
    </div>
  );
}

function ArtifactContent({
  artifact,
  children,
  empty,
}: {
  artifact: PublicStewardArtifact;
  children: (text: string) => ReactNode;
  empty: string;
}) {
  const [remoteText, setRemoteText] = useState<string | null>(null);
  const [remoteError, setRemoteError] = useState<string | null>(null);
  const [remoteLoaded, setRemoteLoaded] = useState(false);
  const artifactUrl = artifact?.url;
  useEffect(() => {
    if (!artifactUrl || artifact?.text) {
      setRemoteText(null);
      setRemoteError(null);
      setRemoteLoaded(false);
      return;
    }
    const url = artifactUrl;
    let cancelled = false;
    setRemoteText(null);
    setRemoteError(null);
    setRemoteLoaded(false);
    async function loadArtifact() {
      try {
        const response = await fetch(url, { cache: 'no-store' });
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const text = await response.text();
        if (!cancelled) {
          setRemoteText(text);
          setRemoteLoaded(true);
        }
      } catch (error) {
        if (!cancelled) setRemoteError(error instanceof Error ? error.message : 'Unable to load artifact');
      }
    }
    void loadArtifact();
    return () => {
      cancelled = true;
    };
  }, [artifact?.text, artifactUrl]);

  const text = artifact?.text || remoteText || '';
  const metadata = artifact && <ArtifactMetadata artifact={artifact} />;
  if (text) {
    return <div className="artifact-content">{metadata}{children(text)}</div>;
  }
  if (artifact?.url) {
    return (
      <div className="artifact-content">
        {metadata}
        <div className={`empty-state compact ${remoteError ? 'artifact-error' : ''}`} role={remoteError ? 'alert' : 'status'}>
          {remoteError ? `Unable to load artifact: ${remoteError}` : remoteLoaded ? 'The remote artifact is empty.' : 'Loading artifact.'}
        </div>
      </div>
    );
  }
  return <div className="artifact-content">{metadata}<div className="empty-state compact">{empty}</div></div>;
}

function ArtifactMetadata({ artifact }: { artifact: NonNullable<PublicStewardArtifact> }) {
  const notes = [
    artifact.mode && artifact.mode !== 'raw' ? `mode: ${artifact.mode}` : '',
    artifact.truncated ? `truncated${artifact.tail_bytes ? `; showing tail (${artifact.tail_bytes} bytes)` : ''}` : '',
    artifact.size > 0 ? `${artifact.size} bytes` : '',
  ].filter(Boolean);
  if (!notes.length) return null;
  return <p className="artifact-metadata">{notes.join(' / ')}</p>;
}

function ReviewSection({ attempt }: { attempt: PublicStewardAttempt }) {
  const review = publicReviewRecord(attempt);
  const reviewerArtifact = attempt.reviewer?.transcript ?? attempt.reviewer?.last_message ?? null;
  return (
    <div className="attempt-review-stack">
      {review ? <ReviewCard review={review} /> : <div className="empty-state compact">No structured review verdict for this attempt</div>}
      <RunSection artifact={reviewerArtifact} run={attempt.reviewer} title="Reviewer transcript" />
    </div>
  );
}

function ValidationList({ validations }: { validations: PublicStewardTaskDetail['validations'] }) {
  const [activeIndex, setActiveIndex] = useState(validations[0]?.index ?? null);
  useEffect(() => {
    setActiveIndex(validations[0]?.index ?? null);
  }, [validations]);
  const activeValidation = validations.find((validation) => validation.index === activeIndex);
  if (!validations.length) return <div className="empty-state compact">No validations for this attempt</div>;
  return (
    <div className="attempt-validation-list">
      <ul className="validation-list">
        {validations.map((validation) => (
          <li key={validation.index}>
            <button
              aria-pressed={activeIndex === validation.index}
              className={`validation-row ${activeIndex === validation.index ? 'active' : ''}`}
              onClick={() => setActiveIndex(validation.index)}
              type="button"
            >
              <span className={`validation-result ${validation.passed ? 'passed' : 'failed'}`}>
                {validation.passed ? <CheckCircle2 size={16} aria-hidden="true" /> : <XCircle size={16} aria-hidden="true" />}
                <b>{validation.passed ? 'Pass' : 'Fail'}</b>
              </span>
              <code>{validation.command.join(' ') || 'No command recorded'}</code>
              <span className="validation-summary">{validation.summary || 'No summary recorded'}</span>
              <span className="validation-time">
                {validation.iteration !== null ? `iteration ${validation.iteration}` : 'iteration -'}
                {validation.completed_at && <time dateTime={validation.completed_at}> · {shortDate(validation.completed_at)}</time>}
              </span>
            </button>
          </li>
        ))}
      </ul>
      {activeValidation && (
        <section className="validation-detail" aria-label="Selected validation">
          <h4>Selected validation</h4>
          <dl className="validation-facts">
            <div><dt>Result</dt><dd>{activeValidation.passed ? 'Pass' : 'Fail'}</dd></div>
            <div><dt>Exit</dt><dd>{activeValidation.exit_code}</dd></div>
            <div><dt>Started</dt><dd><time dateTime={activeValidation.started_at}>{shortDate(activeValidation.started_at)}</time></dd></div>
            <div><dt>Completed</dt><dd><time dateTime={activeValidation.completed_at}>{shortDate(activeValidation.completed_at)}</time></dd></div>
          </dl>
          <p>{activeValidation.summary || 'No validation summary recorded.'}</p>
          <ArtifactContent artifact={activeValidation.log} empty="No validation log was published">
            {(text) => <CodeBlock compact text={text} title="Validation log" />}
          </ArtifactContent>
        </section>
      )}
    </div>
  );
}

function PublicTimelineEvent({ event, index }: { event: PublicStewardEvent; index: number }) {
  const model = publicTimelineModel(event);
  return (
    <li className={`timeline-item ${model.tone}`} id={`task-event-${index}`}>
      <div className="timeline-marker" aria-hidden="true">
        {timelineIcon(event.kind)}
      </div>
      <div className="timeline-card">
        <div className="timeline-head">
          <b className="timeline-kind font-mono">{event.kind}</b>
          <time className="timeline-time font-mono" dateTime={event.created_at}>
            {shortDate(event.created_at)}
          </time>
        </div>
        <div className="timeline-title-row">
          <h3>{model.title}</h3>
          {model.review?.verdict && (
            <span className={`timeline-verdict ${model.review.verdict}`}>
              {model.review.verdict}
            </span>
          )}
        </div>
        {model.description && <p className="timeline-message">{model.description}</p>}
        {model.chips.length > 0 && (
          <div className="timeline-chips">
            {model.chips.map((chip) => (
              <span className={`timeline-chip ${chip.tone || ''}`} key={`${chip.label}-${chip.value}`}>
                <b>{chip.label}</b>
                <span>{chip.value}</span>
              </span>
            ))}
          </div>
        )}
        {model.fields.length > 0 && (
          <dl className="timeline-fields">
            {model.fields.map((field) => (
              <div className="timeline-field" key={`${field.label}-${field.value}`}>
                <dt>{field.label}</dt>
                <dd className={field.kind === 'path' ? 'font-mono path' : undefined}>{field.value}</dd>
              </div>
            ))}
          </dl>
        )}
        {model.review && <PublicReviewTimelineDetails review={model.review} />}
      </div>
    </li>
  );
}

function PublicReviewTimelineDetails({ review }: { review: PublicReviewShape }) {
  const findings = review.findings;
  const gaps = review.validation_gaps;
  if (!review.remaining_risk && findings.length === 0 && gaps.length === 0) return null;
  return (
    <div className="timeline-review">
      {findings.length > 0 && (
        <div>
          <h4>Findings</h4>
          <ul>
            {findings.map((finding, index) => (
              <li key={`${stringValue(finding.title, 'finding')}-${index}`}>
                <b>{stringValue(finding.title, 'Finding')}</b>
                {stringValue(finding.file, '') && (
                  <span className="font-mono">
                    {stringValue(finding.file, '')}
                    {typeof finding.line === 'number' ? `:${finding.line}` : ''}
                  </span>
                )}
              </li>
            ))}
          </ul>
        </div>
      )}
      {gaps.length > 0 && (
        <div>
          <h4>Validation gaps</h4>
          <ul>
            {gaps.map((gap, index) => <li key={`${gap}-${index}`}>{gap}</li>)}
          </ul>
        </div>
      )}
      {review.remaining_risk && (
        <div>
          <h4>Remaining risk</h4>
          <p>{review.remaining_risk}</p>
        </div>
      )}
    </div>
  );
}

function ReviewCard({ review }: { review: PublicReviewRecord }) {
  return (
    <article className="review-card">
      <div className="review-head">
        <div>
          <div className="mono muted">{shortDate(review.created_at)} · attempt {review.attempt}</div>
          <h3>{review.summary || 'Review completed'}</h3>
        </div>
        <span className={`review-verdict ${review.verdict === 'approve' ? 'approve' : review.verdict === 'block' ? 'block' : 'fail'}`}>
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
                  {finding.file}{finding.line !== null ? `:${finding.line}` : ''}
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

function KeyValue({ label, value }: { label: string; value: string }) {
  return (
    <div className="key-value">
      <span>{label}</span>
      <b className="mono">{value}</b>
    </div>
  );
}

function publicReviewRecord(attempt: PublicStewardAttempt): PublicReviewRecord | null {
  if (!attempt.review) return null;
  const stored = attempt.review;
  return {
    attempt: attempt.attempt,
    command: stringValue(stored.command, ''),
    created_at: stringValue(stored.created_at, attempt.updated_at || attempt.started_at || ''),
    event_kind: stringValue(stored.event_kind, 'iteration.review'),
    exit_code: typeof stored.exit_code === 'number' ? stored.exit_code : attempt.reviewer?.exit_code ?? null,
    findings: findingArray(stored.findings),
    remaining_risk: stringValue(stored.remaining_risk, ''),
    summary: stringValue(stored.summary, ''),
    validation_gaps: stringArray(stored.validation_gaps),
    verdict: stringValue(stored.verdict, 'review'),
  };
}

function findingArray(value: unknown): PublicReviewFinding[] {
  if (!Array.isArray(value)) return [];
  return value.filter(isRecord).map((item) => ({
    detail: stringValue(item.detail, ''),
    file: stringValue(item.file, ''),
    line: typeof item.line === 'number' ? item.line : null,
    recommendation: stringValue(item.recommendation, ''),
    severity: stringValue(item.severity, 'info'),
    title: stringValue(item.title, 'Finding'),
  }));
}

function stringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.map(String) : [];
}

function publicTimelineModel(event: PublicStewardEvent): PublicTimelineModel {
  const data = event.data || {};
  const messageRecord = parseRecord(event.message);
  const review = reviewShape(data.review) || reviewShape(messageRecord);
  const base: PublicTimelineModel = {
    title: humanizeKind(event.kind),
    description: cleanMessage(event.message, messageRecord),
    tone: timelineTone(event.kind),
    chips: primitiveChips(data),
    fields: pathFields(data),
    review: null,
  };

  if (event.kind === 'review.finished' && review) {
    return {
      ...base,
      title: review.verdict === 'approve' ? 'Review approved' : 'Review blocked',
      description: review.summary,
      tone: review.verdict === 'approve' ? 'success' : 'danger',
      chips: [
        { label: 'verdict', value: review.verdict, tone: review.verdict === 'approve' ? 'success' : 'danger' },
        { label: 'attempt', value: stringValue(data.attempt, '-') },
        { label: 'findings', value: String(review.findings.length) },
        { label: 'gaps', value: String(review.validation_gaps.length) },
      ],
      review,
    };
  }

  if (event.kind === 'review.failed' || event.kind === 'review.invalid_output') {
    return {
      ...base,
      title: event.kind === 'review.failed' ? 'Review failed' : 'Review returned invalid output',
      description: base.description || stringValue(data.summary, ''),
      tone: 'danger',
      chips: [
        { label: 'attempt', value: stringValue(data.attempt, '-') },
        { label: 'run', value: stringValue(data.review_run, '-') },
        { label: 'retryable', value: stringValue(data.retryable, '-') },
        { label: 'exit', value: stringValue(data.exit_code, '-') },
      ],
    };
  }

  if (event.kind === 'task.status') {
    return {
      ...base,
      title: stringValue(data.summary, `Task moved to ${event.message}`),
      description: '',
      tone: statusTone(event.message),
      chips: [
        { label: 'status', value: event.message, tone: statusTone(event.message) },
        { label: 'phase', value: stringValue(data.phase, '-') },
      ],
    };
  }

  if (event.kind === 'worktree.ready') {
    return {
      ...base,
      title: 'Worktree ready',
      description: '',
      tone: 'success',
      chips: [],
      fields: [
        { label: 'Worktree', value: event.message, kind: 'path' },
        ...fieldIf('Branch', data.branch),
      ],
    };
  }

  if (event.kind === 'patch.saved') {
    return {
      ...base,
      title: 'Patch saved',
      description: '',
      tone: 'success',
      chips: [{ label: 'label', value: stringValue(data.label, '-') }],
      fields: [{ label: 'Patch', value: event.message, kind: 'path' }],
    };
  }

  if (event.kind === 'validation.failed') {
    const failed = Array.isArray(data.failed) ? data.failed : [];
    return {
      ...base,
      title: 'Validation failed',
      description: event.message,
      tone: 'danger',
      chips: [
        { label: 'label', value: stringValue(data.label, '-') },
        { label: 'failed', value: String(failed.length), tone: 'danger' },
      ],
      fields: [
        ...fieldIf('Patch', data.patch_path, 'path'),
        ...failed.slice(0, 3).flatMap((item, index) =>
          isRecord(item) ? fieldIf(`Command ${index + 1}`, commandText(item.command)) : [],
        ),
      ],
    };
  }

  if (event.kind === 'worker.finished'
    || event.kind === 'worker.revision_finished'
    || event.kind === 'worker.integration_revision_finished') {
    return {
      ...base,
      title: event.kind === 'worker.finished' ? 'Worker finished' : 'Worker revision finished',
      description: '',
      tone: event.message === '0' ? 'success' : 'danger',
      chips: [
        { label: 'exit', value: event.message, tone: event.message === '0' ? 'success' : 'danger' },
        ...chipIf('revision', data.revision),
      ],
    };
  }

  if (event.kind === 'worker.integration_revision_requested') {
    return {
      ...base,
      title: `Integration revision ${stringValue(data.revision, '-')} requested`,
      description: 'Patch did not apply on latest main.',
      tone: 'review',
      chips: [
        { label: 'revision', value: stringValue(data.revision, '-') },
      ],
    };
  }

  if (event.kind === 'worker.revision_requested' && review) {
    return {
      ...base,
      title: `Revision ${stringValue(data.revision, '-')} requested`,
      description: review.summary || base.description,
      tone: 'review',
      chips: [
        { label: 'revision', value: stringValue(data.revision, '-') },
        { label: 'review', value: review.verdict || '-' },
        { label: 'gaps', value: String(review.validation_gaps.length) },
      ],
      review,
    };
  }

  if (event.kind.startsWith('integration.')) {
    return {
      ...base,
      title: humanizeKind(event.kind),
      description: '',
      tone: 'review',
      chips: [
        ...chipIf('created', data.created),
        ...chipIf('task', data.integration_task_id || event.message),
      ],
    };
  }

  if (event.kind === 'main.pushed') {
    return {
      ...base,
      title: 'Pushed to main',
      description: '',
      tone: 'success',
      chips: [{ label: 'commit', value: event.message.slice(0, 12), tone: 'success' }],
    };
  }

  if (event.kind === 'task.created') {
    return {
      ...base,
      title: 'Task created',
      description: event.message,
      tone: 'created',
      chips: [],
    };
  }

  return base;
}

function timelineIcon(kind: string): ReactNode {
  if (kind.includes('failed') || kind.includes('recovered') || kind.includes('invalid')) return <XCircle size={14} />;
  if (kind.includes('finished') || kind.includes('ready') || kind.includes('saved')) return <CheckCircle2 size={14} />;
  if (kind.includes('review')) return <ListChecks size={14} />;
  if (kind.includes('worktree') || kind.includes('branch') || kind.includes('push') || kind.includes('integration')) return <GitBranch size={14} />;
  if (kind.includes('status')) return <Activity size={14} />;
  return <Circle size={10} />;
}

function timelineTone(kind: string): PublicTimelineTone {
  if (kind.includes('failed') || kind.includes('recovered') || kind.includes('invalid')) return 'danger';
  if (kind.includes('finished') || kind.includes('ready') || kind.includes('saved')) return 'success';
  if (kind.includes('review') || kind.includes('integration')) return 'review';
  if (kind.includes('created')) return 'created';
  return 'neutral';
}

function statusTone(status: string): PublicTimelineTone {
  if (['failed', 'blocked', 'cancelled'].includes(status)) return 'danger';
  if (['succeeded', 'pushed', 'no_changes'].includes(status)) return 'success';
  if (['reviewing', 'integrating'].includes(status)) return 'review';
  return 'neutral';
}

function reviewShape(value: unknown): PublicReviewShape | null {
  if (!isRecord(value)) return null;
  const findings = Array.isArray(value.findings) ? value.findings.filter(isRecord) : [];
  return {
    verdict: stringValue(value.verdict, ''),
    summary: stringValue(value.summary, ''),
    findings,
    validation_gaps: Array.isArray(value.validation_gaps) ? value.validation_gaps.map(String) : [],
    remaining_risk: stringValue(value.remaining_risk, ''),
  };
}

function cleanMessage(message: string, parsed: Record<string, unknown> | null): string {
  if (!message || parsed) return '';
  return message;
}

function parseRecord(value: string): Record<string, unknown> | null {
  try {
    const parsed = JSON.parse(value) as unknown;
    return isRecord(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

function primitiveChips(data: Record<string, unknown>): PublicTimelineChip[] {
  return Object.entries(data)
    .filter(([, value]) => isPrimitive(value) && !looksLikePath(String(value)))
    .slice(0, 4)
    .map(([key, value]) => ({ label: labelize(key), value: String(value) }));
}

function pathFields(data: Record<string, unknown>): PublicTimelineField[] {
  return Object.entries(data)
    .filter(([, value]) => typeof value === 'string' && looksLikePath(value))
    .slice(0, 4)
    .map(([key, value]) => ({ label: labelize(key), value: String(value), kind: 'path' }));
}

function fieldIf(label: string, value: unknown, kind: 'path' | 'text' = 'text'): PublicTimelineField[] {
  const text = commandText(value);
  return text ? [{ label, value: text, kind }] : [];
}

function chipIf(label: string, value: unknown): PublicTimelineChip[] {
  const text = stringValue(value, '');
  return text ? [{ label, value: text }] : [];
}

function commandText(value: unknown): string {
  if (Array.isArray(value)) return value.map(String).join(' ');
  return typeof value === 'string' ? value : '';
}

function looksLikePath(value: string) {
  return value.startsWith('/') || value.includes('/worktrees/') || value.includes('/transcripts/') || value.includes('/patches/');
}

function humanizeKind(kind: string) {
  return kind
    .split('.')
    .map((part) => part.replace(/_/g, ' '))
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(' ');
}

function labelize(value: string) {
  return value.replace(/_/g, ' ');
}

function stringValue(value: unknown, fallback: string) {
  if (typeof value === 'string' && value.trim()) return value;
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  return fallback;
}

function isPrimitive(value: unknown) {
  return typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean';
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

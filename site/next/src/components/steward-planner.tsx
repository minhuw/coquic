'use client';

import { CheckCircle2, ChevronLeft, ChevronRight, CircleAlert, FileText, LoaderCircle, XCircle } from 'lucide-react';
import { type ReactNode, useEffect, useId, useMemo, useRef, useState } from 'react';

import { PageHeader } from '@/components/page-header';
import { CodeBlock } from '@/components/steward-code-block';
import { ScrollRegion } from '@/components/ui/scroll-region';
import type { PublicArtifact, PublicPlannerRun } from '@/generated/steward-public';
import { decodePublicStewardJson } from '@/lib/steward-schema';

import { StewardStatusLabel } from './steward/shared';

const PAGE_SIZE = 10;

export function StewardPlannerLive() {
  const [runs, setRuns] = useState<PublicPlannerRun[]>([]);
  const [truncated, setTruncated] = useState(false);
  const [updatedAt, setUpdatedAt] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [page, setPage] = useState(1);
  const previousPageRef = useRef<HTMLButtonElement>(null);
  const nextPageRef = useRef<HTMLButtonElement>(null);
  const focusAfterPageChange = useRef<'previous' | 'next' | null>(null);

  useEffect(() => {
    let cancelled = false;
    async function load() {
      try {
        const response = await fetch('/steward/status', { cache: 'no-store' });
        if (!response.ok) throw new Error('status unavailable');
        const decoded = decodePublicStewardJson(await response.text());
        if (!decoded.ok) throw new Error(decoded.reason);
        if (cancelled) return;
        setRuns(decoded.data.planner_runs);
        setTruncated(decoded.data.planner_runs_truncated);
        setUpdatedAt(decoded.data.generated_at);
        setError(null);
      } catch (cause) {
        if (!cancelled) setError(cause instanceof Error ? cause.message : 'status unavailable');
      } finally {
        if (!cancelled) setLoading(false);
      }
    }
    void load();
    return () => {
      cancelled = true;
    };
  }, []);

  const pageCount = Math.max(1, Math.ceil(runs.length / PAGE_SIZE));
  const safePage = Math.min(page, pageCount);
  const pageRuns = useMemo(
    () => runs.slice((safePage - 1) * PAGE_SIZE, safePage * PAGE_SIZE),
    [runs, safePage],
  );
  const summaryState = loading ? 'Loading' : error ? 'Unavailable' : null;

  useEffect(() => {
    if (focusAfterPageChange.current === 'previous') previousPageRef.current?.focus();
    if (focusAfterPageChange.current === 'next') nextPageRef.current?.focus();
    focusAfterPageChange.current = null;
  }, [safePage]);

  function goToPreviousPage() {
    const nextPage = Math.max(1, safePage - 1);
    focusAfterPageChange.current = nextPage === 1 ? 'next' : 'previous';
    setPage(nextPage);
  }

  function goToNextPage() {
    const nextPage = Math.min(pageCount, safePage + 1);
    focusAfterPageChange.current = nextPage === pageCount ? 'previous' : 'next';
    setPage(nextPage);
  }

  return (
    <section aria-label="Planner history" className="steward-planner-page steward-planner-root" data-steward-module="planner" data-steward-root="planner">
      <PageHeader
        actions={(
          <dl aria-label="Planner history summary" className="steward-planner-summary">
            <div>
              <dt>Visible runs</dt>
              <dd>{summaryState ?? runs.length}</dd>
            </div>
            <div className={!summaryState && truncated ? 'steward-planner-summary-warning' : undefined}>
              <dt>Published window</dt>
              <dd>{summaryState ?? (truncated ? 'window truncated' : 'complete')}</dd>
            </div>
            <div>
              <dt>Last update</dt>
              <dd>
                {summaryState ?? (updatedAt
                  ? <time dateTime={updatedAt}>{formatTimestamp(updatedAt)}</time>
                  : 'Unavailable')}
              </dd>
            </div>
          </dl>
        )}
        className="steward-planner-header"
        description="Read-only evidence from standalone signal-planner iterations, retained newest first."
        eyebrow="Steward evidence"
        title="Planner history"
        variant="operations"
      />

      {loading && (
        <PlannerState
          detail="Reading the latest published Steward status."
          icon={<LoaderCircle className="steward-planner-spinner" />}
          title="Loading planner history"
        />
      )}
      {!loading && error && (
        <PlannerState
          detail={error}
          icon={<CircleAlert />}
          recovery="Refresh the page to request the published status again."
          title="Planner history unavailable"
          tone="error"
        />
      )}
      {!loading && !error && !runs.length && <PlannerState icon={<FileText />} title="No planner runs published" detail="The daemon has not published a signal-planner iteration." />}
      {!loading && !error && runs.length > 0 && (
        <>
          <div className="steward-planner-list">
            {pageRuns.map((run) => <PlannerRunRow key={run.id} run={run} />)}
          </div>
          <nav className="steward-planner-pagination" aria-label="Planner history pagination">
            <span aria-live="polite">Page {safePage} of {pageCount}</span>
            <button
              aria-label="Previous planner history page"
              disabled={safePage === 1}
              onClick={goToPreviousPage}
              ref={previousPageRef}
              title="Previous page"
              type="button"
            >
              <ChevronLeft aria-hidden="true" size={18} />
            </button>
            <button
              aria-label="Next planner history page"
              disabled={safePage === pageCount}
              onClick={goToNextPage}
              ref={nextPageRef}
              title="Next page"
              type="button"
            >
              <ChevronRight aria-hidden="true" size={18} />
            </button>
          </nav>
        </>
      )}
    </section>
  );
}

function PlannerRunRow({ run }: { run: PublicPlannerRun }) {
  const titleId = useId();
  const status = run.status;
  const Icon = status === 'succeeded' ? CheckCircle2 : status === 'failed' || status === 'invalid' ? XCircle : LoaderCircle;
  const transcript = run.artifacts.transcript;
  const lastMessage = run.artifacts.last_message;
  return (
    <article aria-labelledby={titleId} className={`steward-planner-run planner-status-${status}`}>
      <header className="steward-planner-run-header">
        <div className="steward-planner-run-title">
          <Icon aria-hidden="true" className={status === 'running' ? 'steward-planner-spinner' : undefined} size={18} />
          <div>
            <h2 id={titleId}>{run.id}</h2>
            <div className="steward-planner-run-time">
              <span>Started <time dateTime={run.started_at}>{formatTimestamp(run.started_at)}</time></span>
              {run.completed_at
                ? <span>Completed <time dateTime={run.completed_at}>{formatTimestamp(run.completed_at)}</time></span>
                : <span>Completion in progress</span>}
            </div>
          </div>
        </div>
        <StewardStatusLabel
          className={`steward-planner-status planner-status-label-${status}`}
          status={status}
        />
      </header>
      <dl className="steward-planner-metrics">
        <div><dt>Accepted</dt><dd>{run.accepted_count}</dd></div>
        <div><dt>Proposed</dt><dd>{run.proposed_count}</dd></div>
        <div><dt>Signals consumed</dt><dd>{run.consumed_signal_ids.length}</dd></div>
        <div><dt>Exit</dt><dd>{run.diagnostics.exit_code ?? '-'}</dd></div>
      </dl>
      <div className="steward-planner-run-context">
        <p className="steward-planner-diagnostic">
          <span>Diagnostic</span>
          <strong>{run.diagnostics.summary || run.diagnostics.error_category}</strong>
        </p>
        <p className="steward-planner-signals">
          <span>Signals</span>
          <strong>{run.consumed_signal_ids.length ? `Consumed: ${run.consumed_signal_ids.join(', ')}` : 'No signal IDs consumed'}</strong>
        </p>
      </div>
      <details className="steward-planner-artifacts">
        <summary>
          <span><FileText aria-hidden="true" size={16} /> Artifacts</span>
          <span>Transcript and last message</span>
        </summary>
        <div className="steward-planner-artifact-grid">
          <ArtifactSummary label="Transcript" artifact={transcript ?? null} />
          <ArtifactSummary label="Last message" artifact={lastMessage ?? null} />
        </div>
      </details>
    </article>
  );
}

function ArtifactSummary({ artifact, label }: { artifact: PublicArtifact; label: string }) {
  if (!artifact) {
    return (
      <section aria-label={`${label} artifact`} className="steward-planner-artifact steward-planner-artifact-missing">
        <header><h3>{label}</h3><span>Not produced</span></header>
        <p>No public artifact was published for this run.</p>
      </section>
    );
  }
  const availability = artifact.availability.replaceAll('_', ' ');
  return (
    <section aria-label={`${label} artifact`} className="steward-planner-artifact">
      <header>
        <h3>{label}</h3>
        <span>{availability}{artifact.truncated ? ' / truncated' : ''}</span>
      </header>
      {artifact.text
        ? (
          <ArtifactScroll label={label}>
            <CodeBlock
              className="steward-planner-artifact-code !min-w-max !overflow-visible"
              compact
              showLineNumbers={false}
              text={artifact.text}
              title={label}
            />
          </ArtifactScroll>
        )
        : <p>No public text was retained for this artifact.</p>}
    </section>
  );
}

function ArtifactScroll({ children, label }: { children: ReactNode; label: string }) {
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    // Artifact evidence remains keyboard-addressable even before overflow measurement settles.
    if (ref.current) ref.current.tabIndex = 0;
  }, []);

  return (
    <ScrollRegion
      aria-label={`${label} artifact text`}
      axis="both"
      className="steward-planner-artifact-scroll"
      ref={ref}
      role="region"
    >
      {children}
    </ScrollRegion>
  );
}

function PlannerState({
  detail,
  icon,
  recovery,
  title,
  tone = 'neutral',
}: {
  detail?: string;
  icon: ReactNode;
  recovery?: string;
  title: string;
  tone?: 'error' | 'neutral';
}) {
  return (
    <div className={`steward-planner-state steward-planner-state-${tone}`} role={tone === 'error' ? 'alert' : 'status'}>
      {icon}
      <strong>{title}</strong>
      {detail && <span>{detail}</span>}
      {recovery && <span>{recovery}</span>}
    </div>
  );
}

function formatTimestamp(value: string) {
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? value
    : date.toLocaleString(undefined, {
        day: 'numeric',
        hour: 'numeric',
        minute: '2-digit',
        month: 'short',
        second: '2-digit',
        timeZoneName: 'short',
        year: 'numeric',
      });
}

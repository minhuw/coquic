'use client';

import { CheckCircle2, ChevronLeft, ChevronRight, CircleAlert, FileText, LoaderCircle, XCircle } from 'lucide-react';
import { type ReactNode, useEffect, useMemo, useState } from 'react';

import type { PublicArtifact, PublicPlannerRun } from '@/generated/steward-public';
import { decodePublicStewardJson } from '@/lib/steward-schema';

const PAGE_SIZE = 10;

export function StewardPlannerLive() {
  const [runs, setRuns] = useState<PublicPlannerRun[]>([]);
  const [truncated, setTruncated] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [page, setPage] = useState(1);

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

  return (
    <section className="steward-planner-page" aria-labelledby="steward-planner-title">
      <header className="steward-planner-header">
        <div>
          <span className="eyebrow">Read-only monitor</span>
          <h1 id="steward-planner-title">Planner history</h1>
          <p>Standalone signal-planner iterations, newest first.</p>
        </div>
        <div className="steward-planner-summary" aria-label="Planner history summary">
          <span>{runs.length} visible runs</span>
          {truncated && <strong>window truncated</strong>}
        </div>
      </header>

      {loading && <PlannerState icon={<LoaderCircle className="animate-spin" />} title="Loading planner history" />}
      {!loading && error && <PlannerState icon={<CircleAlert />} title="Planner history unavailable" detail={error} />}
      {!loading && !error && !runs.length && <PlannerState icon={<FileText />} title="No planner runs published" detail="The daemon has not published a signal-planner iteration." />}
      {!loading && !error && runs.length > 0 && (
        <>
          <div className="steward-planner-list">
            {pageRuns.map((run) => <PlannerRunCard key={run.id} run={run} />)}
          </div>
          <nav className="steward-planner-pagination" aria-label="Planner history pagination">
            <span>Page {safePage} of {pageCount}</span>
            <button
              aria-label="Previous planner history page"
              disabled={safePage === 1}
              onClick={() => setPage(Math.max(1, safePage - 1))}
              type="button"
            >
              <ChevronLeft size={16} />
            </button>
            <button
              aria-label="Next planner history page"
              disabled={safePage === pageCount}
              onClick={() => setPage(Math.min(pageCount, safePage + 1))}
              type="button"
            >
              <ChevronRight size={16} />
            </button>
          </nav>
        </>
      )}
    </section>
  );
}

function PlannerRunCard({ run }: { run: PublicPlannerRun }) {
  const status = run.status;
  const Icon = status === 'succeeded' ? CheckCircle2 : status === 'failed' || status === 'invalid' ? XCircle : LoaderCircle;
  const transcript = run.artifacts.transcript;
  const lastMessage = run.artifacts.last_message;
  return (
    <article className={`steward-planner-run planner-status-${status}`}>
      <header className="steward-planner-run-header">
        <div className="steward-planner-run-title">
          <Icon aria-hidden="true" size={17} />
          <div>
            <h2>{run.id}</h2>
            <p>{formatTimestamp(run.started_at)}{run.completed_at ? ` to ${formatTimestamp(run.completed_at)}` : ' in progress'}</p>
          </div>
        </div>
        <span className="steward-planner-status">{status}</span>
      </header>
      <dl className="steward-planner-metrics">
        <div><dt>Accepted</dt><dd>{run.accepted_count}</dd></div>
        <div><dt>Proposed</dt><dd>{run.proposed_count}</dd></div>
        <div><dt>Signals consumed</dt><dd>{run.consumed_signal_ids.length}</dd></div>
        <div><dt>Exit</dt><dd>{run.diagnostics.exit_code ?? '-'}</dd></div>
      </dl>
      <p className="steward-planner-diagnostic">{run.diagnostics.summary || run.diagnostics.error_category}</p>
      <p className="steward-planner-signals">
        {run.consumed_signal_ids.length ? `Consumed: ${run.consumed_signal_ids.join(', ')}` : 'No signal IDs consumed'}
      </p>
      <details className="steward-planner-artifacts">
        <summary><FileText size={15} /> Artifacts</summary>
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
    return <div className="steward-planner-artifact"><b>{label}</b><span>Not produced</span></div>;
  }
  return (
    <div className="steward-planner-artifact">
      <b>{label}</b>
      <span>{artifact.availability}{artifact.truncated ? ' / truncated' : ''}</span>
      {artifact.text && <pre>{artifact.text}</pre>}
    </div>
  );
}

function PlannerState({ detail, icon, title }: { detail?: string; icon: ReactNode; title: string }) {
  return <div className="steward-planner-state">{icon}<strong>{title}</strong>{detail && <span>{detail}</span>}</div>;
}

function formatTimestamp(value: string) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
}

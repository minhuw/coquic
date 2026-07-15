import type { Metadata } from 'next';
import Script from 'next/script';

import { PageHeader } from '@/components/page-header';

export const metadata: Metadata = {
  title: 'CoQUIC Performance Comparison',
  other: {
    'coquic-perf-marker': 'coquic-perf-comparison-v1',
  },
};

export default function PerformancePage() {
  return (
    <main className="coquic-page performance-page" id="performance-page" data-testid="performance-page">
      <PageHeader eyebrow="QUIC performance" title="CoQUIC Performance Comparison" variant="evidence" />

      <section className="performance-summary" aria-label="Benchmark scope and availability">
        <div className="performance-summary__scope">
          <span className="performance-kicker">Evidence surface</span>
          <p>Current benchmark results are shown first. Historical comparisons hydrate separately.</p>
        </div>
        <dl className="performance-summary__facts">
          <div>
            <dt>Source</dt>
            <dd id="performance-source">Waiting for perf-results.json</dd>
          </div>
          <div>
            <dt>Generated</dt>
            <dd id="performance-timestamp">Waiting for benchmark timestamp</dd>
          </div>
          <div>
            <dt>Availability</dt>
            <dd id="performance-availability">Checking benchmark data</dd>
          </div>
        </dl>
      </section>

      <section className="performance-workspace" aria-label="Performance comparison">
        <div className="plot-grid" id="plot-grid">
          <section className="performance-controls" id="performance-controls" aria-label="Benchmark controls">
            <div className="performance-controls__head">
              <div>
                <span className="performance-kicker">Compare</span>
                <h2>Benchmark mode</h2>
              </div>
              <button
                className="performance-filter-toggle"
                id="performance-filter-toggle"
                type="button"
                aria-controls="performance-filter-panel"
                aria-expanded="false"
              >
                Filters
              </button>
            </div>
            <div id="performance-mode-tabs" />
            <div className="performance-filter-summary" aria-live="polite">
              <span id="performance-filter-count">0 filters active</span>
              <span id="performance-filter-selection">All implementations</span>
            </div>
            <div id="performance-filter-panel" className="performance-filter-panel" hidden>
              <div id="performance-filters" />
            </div>
          </section>

          <section
            className="performance-result performance-result--ranking"
            id="performance-ranking"
            aria-labelledby="performance-ranking-title"
            aria-busy="true"
            data-state="loading"
          >
            <div className="performance-result__heading">
              <div>
                <span className="performance-kicker">Current result</span>
                <h2 id="performance-ranking-title">Ranking</h2>
              </div>
              <span className="performance-result__unit" id="performance-ranking-unit">Waiting</span>
            </div>
            <div
              className="performance-skeleton performance-skeleton--ranking"
              id="performance-current-skeleton"
              aria-hidden="true"
            >
              <span />
              <span />
              <span />
              <span />
            </div>
            <div id="performance-current-state" data-state="loading" role="status">
              Loading current benchmark evidence.
            </div>
            <div id="performance-ranking-content" hidden>
              <div
                id="plot-panel"
                role="tabpanel"
                aria-labelledby="plot-tab-bulk"
                tabIndex={0}
                hidden
              />
            </div>
          </section>

          <section
            className="performance-result performance-result--history"
            id="performance-history"
            aria-labelledby="performance-history-title"
            aria-busy="true"
            data-state="loading"
          >
            <div className="performance-result__heading">
              <div>
                <span className="performance-kicker">Retained evidence</span>
                <h2 id="performance-history-title">Trend</h2>
              </div>
              <span className="performance-result__unit" id="performance-history-unit">History loading</span>
            </div>
            <div id="performance-history-state" data-state="loading" role="status">
              Loading retained benchmark history.
            </div>
            <div id="performance-trend" className="performance-trend" tabIndex={-1} />
          </section>
        </div>
      </section>

      <dialog
        className="performance-dialog performance-dialog--detail"
        id="perf-detail-dialog"
        aria-labelledby="perf-detail-title"
      >
        <div className="performance-dialog__surface">
          <header className="performance-dialog__head">
            <div>
              <span className="performance-kicker">Run detail</span>
              <h2 id="perf-detail-title">Performance details</h2>
            </div>
            <button className="performance-dialog__close" id="perf-detail-close" type="button" aria-label="Close performance details">
              Close
            </button>
          </header>
          <div className="performance-dialog__body" id="perf-detail-body" />
        </div>
      </dialog>

      <dialog
        className="performance-dialog performance-dialog--flamegraph"
        id="perf-flamegraph-dialog"
        aria-labelledby="perf-flamegraph-title"
      >
        <div className="performance-dialog__surface">
          <header className="performance-dialog__head">
            <div>
              <span className="performance-kicker">Profile artifact</span>
              <h2 id="perf-flamegraph-title">Flamegraph</h2>
            </div>
            <button className="performance-dialog__close" id="perf-flamegraph-close" type="button" aria-label="Close flamegraph">
              Close
            </button>
          </header>
          <div className="performance-dialog__body" id="perf-flamegraph-body" />
        </div>
      </dialog>

      <Script src="/perf-comparison.js" strategy="afterInteractive" type="module" />
    </main>
  );
}

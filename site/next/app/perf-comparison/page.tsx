import type { Metadata } from 'next';

import { PageHeader } from '@/components/page-header';

import { PerformanceLoader } from './performance-loader';
import styles from './performance.module.css';

export const metadata: Metadata = {
  title: 'CoQUIC Performance Comparison',
  other: {
    'coquic-perf-marker': 'coquic-perf-comparison-v1',
  },
};

export default function PerformancePage() {
  return (
    <main className={styles.root} id="performance-page" data-testid="performance-page">
      <PageHeader
        eyebrow="QUIC performance"
        title="CoQUIC Performance Comparison"
        description="Compare throughput and request rates across QUIC implementations, then inspect retained runs for performance changes over time."
        variant="evidence"
      />

      <section className={styles.summary} aria-label="Benchmark scope and availability">
        <div className={styles.summaryScope}>
          <span className={styles.kicker}>Evidence surface</span>
          <p>Reproducible host benchmarks with current rankings and retained historical evidence.</p>
        </div>
        <dl className={styles.summaryFacts}>
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

      <section className={styles.workspace} aria-label="Performance comparison">
        <div id="plot-grid">
          <section className={styles.controls} id="performance-controls" aria-label="Benchmark controls">
            <div className={styles.controlsHead}>
              <div>
                <span className={styles.kicker}>Compare</span>
                <h2>Benchmark mode</h2>
              </div>
              <button
                className={styles.filterToggle}
                id="performance-filter-toggle"
                type="button"
                aria-controls="performance-filter-panel"
                aria-expanded="false"
              >
                Filters
              </button>
            </div>
            <div id="performance-mode-tabs" />
            <div className={styles.filterSummary} aria-live="polite">
              <span id="performance-filter-count">0 filters active</span>
              <span id="performance-filter-selection">All implementations</span>
            </div>
            <div id="performance-filter-panel" className={styles.filterPanel} hidden>
              <div id="performance-filters" />
            </div>
          </section>

          <section
            className={`${styles.result} ${styles.resultRanking}`}
            id="performance-ranking"
            aria-labelledby="performance-ranking-title"
            aria-busy="true"
            data-state="loading"
          >
            <div className={styles.resultHeading}>
              <div>
                <span className={styles.kicker}>Current result</span>
                <h2 id="performance-ranking-title">Ranking</h2>
              </div>
              <span className={styles.resultUnit} id="performance-ranking-unit">Waiting</span>
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
            className={`${styles.result} ${styles.resultHistory}`}
            id="performance-history"
            aria-labelledby="performance-history-title"
            aria-busy="true"
            data-state="loading"
          >
            <div className={styles.resultHeading}>
              <div>
                <span className={styles.kicker}>Retained evidence</span>
                <h2 id="performance-history-title">Trend</h2>
              </div>
              <span className={styles.resultUnit} id="performance-history-unit">History loading</span>
            </div>
            <div id="performance-history-state" data-state="loading" role="status">
              Loading retained benchmark history.
            </div>
            <div id="performance-trend" tabIndex={-1} />
          </section>
        </div>
      </section>

      <dialog
        className={`${styles.dialog} ${styles.dialogDetail}`}
        id="perf-detail-dialog"
        aria-labelledby="perf-detail-title"
      >
        <div className={styles.dialogSurface}>
          <header className={styles.dialogHead}>
            <div>
              <span className={styles.kicker}>Run detail</span>
              <h2 id="perf-detail-title">Performance details</h2>
            </div>
            <button className={styles.dialogClose} id="perf-detail-close" type="button" aria-label="Close performance details">
              Close
            </button>
          </header>
          <div className={styles.dialogBody} id="perf-detail-body" />
        </div>
      </dialog>

      <dialog
        className={`${styles.dialog} ${styles.dialogFlamegraph}`}
        id="perf-flamegraph-dialog"
        aria-labelledby="perf-flamegraph-title"
      >
        <div className={styles.dialogSurface}>
          <header className={styles.dialogHead}>
            <div>
              <span className={styles.kicker}>Profile artifact</span>
              <h2 id="perf-flamegraph-title">Flamegraph</h2>
            </div>
            <button className={styles.dialogClose} id="perf-flamegraph-close" type="button" aria-label="Close flamegraph">
              Close
            </button>
          </header>
          <div className={styles.dialogBody} id="perf-flamegraph-body" />
        </div>
      </dialog>

      <PerformanceLoader />
    </main>
  );
}

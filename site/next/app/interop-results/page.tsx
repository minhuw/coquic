import type { Metadata } from 'next';
import Script from 'next/script';

import { PageHeader } from '@/components/page-header';

import styles from './interop.module.css';

export const metadata: Metadata = {
  title: 'CoQUIC Interop Results',
  other: {
    'coquic-interop-marker': 'coquic-interop-results-v1',
  },
};

export default function InteropPage() {
  return (
    <main
      className={styles.root}
      aria-label="CoQUIC interop evidence"
      aria-busy="true"
      data-interop-state="loading"
      data-interop-root="true"
    >
      <PageHeader
        className={styles.pageHeader}
        eyebrow="protocol evidence / generated interop"
        title="CoQUIC Interop Matrix"
        description={
          <>
            <span id="data-source-label">waiting for interop-results.json</span>
            <span className={styles.scope}>Scope: CoQUIC as client or server across reported peer lanes.</span>
          </>
        }
        variant="evidence"
      />

      <section className={styles.summarySection} aria-labelledby="interop-summary-title">
        <div className={styles.summaryHead}>
          <div>
            <p className={styles.sectionLabel} id="interop-summary-title">Snapshot summary</p>
            <p className={styles.state} id="interop-state" role="status" aria-live="polite">
              Loading interop evidence.
            </p>
          </div>
          <dl className={styles.runContext} data-interop-context aria-label="Interop snapshot context">
            <div>
              <dt>Generated</dt>
              <dd data-interop-generated>Awaiting snapshot</dd>
            </div>
            <div>
              <dt>Event</dt>
              <dd data-interop-event>Awaiting snapshot</dd>
            </div>
            <div>
              <dt>Commit</dt>
              <dd data-interop-commit>Awaiting snapshot</dd>
            </div>
          </dl>
        </div>

        <dl className={styles.legend} aria-label="Compatibility result summary">
          <div className={`${styles.legendItem} ${styles.statusSuccess}`}>
            <dt>PASS</dt>
            <dd data-interop-count="pass">-</dd>
          </div>
          <div className={`${styles.legendItem} ${styles.statusWarning}`}>
            <dt>UNSUPPORTED</dt>
            <dd data-interop-count="unsupported">-</dd>
          </div>
          <div className={`${styles.legendItem} ${styles.statusNeutral}`}>
            <dt>PEER BROKEN</dt>
            <dd data-interop-count="peer-broken">-</dd>
          </div>
          <div className={`${styles.legendItem} ${styles.statusKnownPeer}`}>
            <dt>KNOWN PEER ISSUE</dt>
            <dd data-interop-count="known-peer-broken">-</dd>
          </div>
          <div className={`${styles.legendItem} ${styles.statusDanger}`}>
            <dt>FAIL</dt>
            <dd data-interop-count="failed">-</dd>
          </div>
          <div className={`${styles.legendItem} ${styles.statusNeutral}`}>
            <dt>NOT REPORTED</dt>
            <dd data-interop-count="not-reported">-</dd>
          </div>
        </dl>

        <p className={styles.conclusion} id="interop-conclusion">
          Conclusion pending snapshot availability.
        </p>
      </section>

      <section className={styles.matrixSection} aria-labelledby="interop-matrix-title">
        <div className={styles.matrixHeading}>
          <div>
            <p className={styles.sectionLabel}>Evidence matrix</p>
            <h2 id="interop-matrix-title">CoQUIC interop results matrix</h2>
          </div>
          <p className={styles.matrixNote}>Rows preserve client/server direction; columns follow the published test order.</p>
        </div>
        <div
          className={styles.matrixWrap}
          id="interop-matrix-region"
          role="region"
          aria-label="CoQUIC interop results matrix"
          aria-describedby="interop-matrix-help"
          aria-busy="true"
        >
          <p className={styles.visuallyHidden} id="interop-matrix-help">
            Scroll within this bounded region to inspect all test cases. Use Tab to move through result details.
          </p>
          <table className={styles.matrix} aria-label="CoQUIC interop test-case results">
            <thead id="matrix-head" />
            <tbody id="matrix-body" />
          </table>
        </div>
      </section>

      <Script src="/interop-results.js" strategy="afterInteractive" type="module" />
    </main>
  );
}

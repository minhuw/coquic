import type { Metadata } from 'next';
import Script from 'next/script';

import { PageHeader } from '@/components/page-header';

export const metadata: Metadata = {
  title: 'CoQUIC Interop Results',
  other: {
    'coquic-interop-marker': 'coquic-interop-results-v1',
  },
};

export default function InteropPage() {
  return (
    <main
      className="coquic-page interop-page"
      aria-label="CoQUIC interop evidence"
      aria-busy="true"
      data-interop-state="loading"
    >
      <PageHeader
        className="interop-page-header"
        eyebrow="protocol evidence / generated interop"
        title="CoQUIC Interop Matrix"
        description={
          <>
            <span id="data-source-label">waiting for interop-results.json</span>
            <span className="interop-scope">Scope: CoQUIC as client or server across reported peer lanes.</span>
          </>
        }
      />

      <section className="interop-summary-section" aria-labelledby="interop-summary-title">
        <div className="interop-summary-head">
          <div>
            <p className="interop-section-label" id="interop-summary-title">Snapshot summary</p>
            <p className="interop-state" id="interop-state" role="status" aria-live="polite">
              Loading interop evidence.
            </p>
          </div>
          <dl className="interop-run-context" aria-label="Interop snapshot context">
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

        <dl className="interop-legend" aria-label="Compatibility result summary">
          <div className="interop-legend-item succeeded">
            <dt>PASS</dt>
            <dd data-interop-count="pass">-</dd>
          </div>
          <div className="interop-legend-item unsupported">
            <dt>UNSUPPORTED</dt>
            <dd data-interop-count="unsupported">-</dd>
          </div>
          <div className="interop-legend-item peer-broken">
            <dt>PEER BROKEN</dt>
            <dd data-interop-count="peer-broken">-</dd>
          </div>
          <div className="interop-legend-item known-peer-broken">
            <dt>KNOWN PEER ISSUE</dt>
            <dd data-interop-count="known-peer-broken">-</dd>
          </div>
          <div className="interop-legend-item failed">
            <dt>FAIL</dt>
            <dd data-interop-count="failed">-</dd>
          </div>
          <div className="interop-legend-item not-reported">
            <dt>NOT REPORTED</dt>
            <dd data-interop-count="not-reported">-</dd>
          </div>
        </dl>

        <p className="interop-conclusion" id="interop-conclusion">
          Conclusion pending snapshot availability.
        </p>
      </section>

      <section className="interop-matrix-section" aria-labelledby="interop-matrix-title">
        <div className="interop-matrix-heading">
          <div>
            <p className="interop-section-label">Evidence matrix</p>
            <h2 id="interop-matrix-title">CoQUIC interop results matrix</h2>
          </div>
          <p className="interop-matrix-note">Rows preserve client/server direction; columns follow the published test order.</p>
        </div>
        <div
          className="compat-wrap"
          id="interop-matrix-region"
          role="region"
          aria-label="CoQUIC interop results matrix"
          aria-describedby="interop-matrix-help"
          aria-busy="true"
        >
          <p className="interop-visually-hidden" id="interop-matrix-help">
            Scroll within this bounded region to inspect all test cases. Use Tab to move through result details.
          </p>
          <table className="compat-matrix" aria-label="CoQUIC interop test-case results">
            <thead id="matrix-head" />
            <tbody id="matrix-body" />
          </table>
        </div>
      </section>

      <Script src="/interop-results.js" strategy="afterInteractive" type="module" />
    </main>
  );
}

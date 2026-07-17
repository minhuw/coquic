import type { Metadata } from 'next';
import Script from 'next/script';
import Link from 'next/link';
import { ExternalLink, FileJson } from 'lucide-react';

import { ComplianceAction, CompliancePage, complianceStyles as styles } from '@/components/compliance';

export const metadata: Metadata = {
  title: 'CoQUIC Coverage Results',
  other: {
    'coquic-coverage-marker': 'coquic-coverage-results-v1',
  },
};

export default function CoveragePage() {
  return (
    <CompliancePage
        eyebrow="LLVM source coverage"
        title="CoQUIC Coverage Report"
        description={
          <div className={styles.coverageSource}>
            <p id="coverage-source-label" aria-live="polite">
              waiting for coverage-results.json
            </p>
            <dl className={styles.coverageSourceMeta} aria-label="Coverage source metadata">
              <div>
                <dt>Generated</dt>
                <dd id="coverage-generated-at">awaiting</dd>
              </div>
              <div>
                <dt>Event</dt>
                <dd id="coverage-event">awaiting</dd>
              </div>
              <div>
                <dt>Commit</dt>
                <dd id="coverage-commit">awaiting</dd>
              </div>
            </dl>
          </div>
        }
        actions={
          <>
            <ComplianceAction asChild variant="outline" size="sm">
              <Link href="/coverage/index.html">
                <ExternalLink aria-hidden="true" />
                Open LLVM HTML
              </Link>
            </ComplianceAction>
            <ComplianceAction asChild variant="outline" size="sm">
              <Link href="./coverage-results.json">
                <FileJson aria-hidden="true" />
                Download JSON
              </Link>
            </ComplianceAction>
          </>
        }
      >
      <section
        className={styles.coverageEvidence}
        id="coverage-evidence"
        data-coverage-state="loading"
        aria-busy="true"
        aria-label="Coverage evidence"
      >
        <div id="coverage-status" className={styles.coverageStatus} role="status" aria-live="polite">
          Loading coverage-results.json.
        </div>

        <section id="summary-grid" aria-label="Coverage totals" className={styles.coverageSummary} />

        <div className={styles.coverageDetailGrid} aria-label="Coverage details">
          <section className={styles.coverageEvidencePanel} aria-labelledby="components-heading">
            <header className={styles.coveragePanelHeading}>
              <div>
                <h2 id="components-heading">Components</h2>
                <p>Line coverage by source area</p>
              </div>
            </header>
            <div id="component-list" />
          </section>

          <section className={styles.coverageEvidencePanel} aria-labelledby="files-heading">
            <header className={styles.coveragePanelHeading}>
              <div>
                <h2 id="files-heading">Lowest Files</h2>
                <p>Files kept in report order</p>
              </div>
            </header>
            <div id="file-list" />
          </section>
        </div>
      </section>

      <Script src="/coverage-results.js" strategy="afterInteractive" type="module" />
    </CompliancePage>
  );
}

import type { Metadata } from 'next';
import Script from 'next/script';
import Link from 'next/link';
import { ExternalLink, FileJson } from 'lucide-react';

import { PageHeader } from '@/components/page-header';
import { Button } from '@/components/ui/button';

export const metadata: Metadata = {
  title: 'CoQUIC Coverage Results',
  other: {
    'coquic-coverage-marker': 'coquic-coverage-results-v1',
  },
};

export default function CoveragePage() {
  return (
    <main className="coquic-page compliance-page">
      <PageHeader
        eyebrow="LLVM source coverage"
        title="CoQUIC Coverage Report"
        description={
          <div className="coverage-source-block">
            <p id="coverage-source-label" aria-live="polite">
              waiting for coverage-results.json
            </p>
            <dl className="coverage-source-meta" aria-label="Coverage source metadata">
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
          <div className="compliance-actions">
            <Button asChild variant="outline" size="sm">
              <Link href="/coverage/index.html">
                <ExternalLink aria-hidden="true" />
                Open LLVM HTML
              </Link>
            </Button>
            <Button asChild variant="outline" size="sm">
              <Link href="./coverage-results.json">
                <FileJson aria-hidden="true" />
                Download JSON
              </Link>
            </Button>
          </div>
        }
      />

      <section
        className="coverage-evidence"
        id="coverage-evidence"
        data-coverage-state="loading"
        aria-busy="true"
        aria-label="Coverage evidence"
      >
        <div id="coverage-status" className="coverage-status" role="status" aria-live="polite">
          Loading coverage-results.json.
        </div>

        <section className="coverage-summary" id="summary-grid" aria-label="Coverage totals" />

        <div className="coverage-detail-grid" aria-label="Coverage details">
          <section className="coverage-evidence-panel" aria-labelledby="components-heading">
            <header className="coverage-panel-heading">
              <div>
                <h2 id="components-heading">Components</h2>
                <p>Line coverage by source area</p>
              </div>
            </header>
            <div id="component-list" />
          </section>

          <section className="coverage-evidence-panel" aria-labelledby="files-heading">
            <header className="coverage-panel-heading">
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
    </main>
  );
}

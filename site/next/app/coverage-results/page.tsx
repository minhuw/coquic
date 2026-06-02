import type { Metadata } from 'next';
import Script from 'next/script';
import Link from 'next/link';

import { DemoNav } from '@/components/demo-nav';
import { Button } from '@/components/ui/button';
import { Card, CardHeader, CardTitle } from '@/components/ui/card';

export const metadata: Metadata = {
  title: 'CoQUIC Coverage Results',
  other: {
    'coquic-coverage-marker': 'coquic-coverage-results-v1',
  },
};

export default function CoveragePage() {
  return (
    <main className="coquic-page">
      <DemoNav active="coverage" />

      <section className="grid gap-5 border-b border-[var(--line)] py-7 md:grid-cols-[minmax(0,1fr)_auto] md:items-end">
        <div>
          <span className="eyebrow">LLVM source coverage</span>
          <h1 className="page-title">CoQUIC Coverage Report</h1>
          <p className="mt-2 max-w-[760px] text-[15px] leading-relaxed text-[var(--soft)]" id="coverage-source-label">
            waiting for coverage-results.json
          </p>
        </div>
        <div className="flex flex-wrap justify-start gap-2 md:justify-end">
          <Button asChild variant="outline" size="sm">
            <Link href="/coverage/index.html">Open LLVM HTML</Link>
          </Button>
          <Button asChild variant="outline" size="sm">
            <Link href="./coverage-results.json">Download JSON</Link>
          </Button>
        </div>
      </section>

      <section className="mt-5 grid gap-3 md:grid-cols-3" id="summary-grid" aria-label="Coverage totals" />

      <section className="coverage-grid md:grid-cols-2" aria-label="Coverage details">
        <Card className="component-panel">
          <CardHeader className="panel-head">
            <div>
              <CardTitle>Components</CardTitle>
              <p>Line coverage by source area</p>
            </div>
          </CardHeader>
          <div id="component-list" />
        </Card>

        <Card className="file-panel">
          <CardHeader className="panel-head">
            <div>
              <CardTitle>Lowest Files</CardTitle>
              <p>Files sorted by line coverage</p>
            </div>
          </CardHeader>
          <div id="file-list" />
        </Card>
      </section>

      <Script src="/coverage-results.js" strategy="afterInteractive" type="module" />
    </main>
  );
}

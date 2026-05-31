import type { Metadata } from 'next';
import Script from 'next/script';
import { Clock3 } from 'lucide-react';

import { DemoNav } from '@/components/demo-nav';
import { PageHeader } from '@/components/page-header';
import { Card, CardHeader, CardTitle } from '@/components/ui/card';

export const metadata: Metadata = {
  title: 'CoQUIC Performance Comparison',
  other: {
    'coquic-perf-marker': 'coquic-perf-comparison-v1',
  },
};

export default function PerformancePage() {
  return (
    <main className="coquic-page">
      <DemoNav active="performance" />
      <PageHeader eyebrow="QUIC performance" title="CoQUIC Performance Comparison" />

      <section className="comparison-shell" aria-label="Performance comparison">
        <Card className="chart-panel">
          <CardHeader className="panel-head">
            <div>
              <CardTitle>Performance Barplots</CardTitle>
            </div>
            <span
              className="source-time"
              id="data-source-label"
              tabIndex={0}
              title="waiting"
              data-tooltip="waiting"
              aria-label="Benchmark data time: waiting"
            >
              <Clock3 aria-hidden="true" />
            </span>
          </CardHeader>
          <div className="plot-grid" id="plot-grid" />
        </Card>

        <Card className="trend-panel">
          <CardHeader className="panel-head">
            <div>
              <CardTitle>Daily Performance Trends</CardTitle>
              <p id="history-source-label">waiting for perf-history.json</p>
            </div>
          </CardHeader>
          <div className="trend-grid" id="trend-grid" />
        </Card>
      </section>

      <Script src="/perf-comparison.js" strategy="afterInteractive" type="module" />
    </main>
  );
}

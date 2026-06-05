import type { Metadata } from 'next';
import Script from 'next/script';

import { DemoNav } from '@/components/demo-nav';
import { PageHeader } from '@/components/page-header';
import { Card } from '@/components/ui/card';

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
          <div className="plot-grid" id="plot-grid" />
        </Card>
      </section>

      <Script src="/perf-comparison.js" strategy="afterInteractive" type="module" />
    </main>
  );
}

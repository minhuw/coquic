import type { Metadata } from 'next';
import Link from 'next/link';
import { ExternalLink, FileJson, FileText } from 'lucide-react';

import { DemoNav } from '@/components/demo-nav';
import { Button } from '@/components/ui/button';

export const metadata: Metadata = {
  title: 'CoQUIC Duvet RFC Compliance',
  other: {
    'coquic-duvet-marker': 'coquic-duvet-report-v1',
  },
};

export default function DuvetPage() {
  return (
    <main className="coquic-page">
      <DemoNav active="duvet" />

      <section className="grid gap-5 border-b border-[var(--line)] py-7 md:grid-cols-[minmax(0,1fr)_auto] md:items-end">
        <div>
          <span className="eyebrow">RFC traceability</span>
          <h1 className="page-title">CoQUIC Duvet Report</h1>
          <p className="mt-2 max-w-[760px] text-[15px] leading-relaxed text-[var(--soft)]">
            Duvet maps extracted RFC requirements to implementation and test annotations in the CoQUIC source tree.
          </p>
        </div>
        <div className="flex flex-wrap justify-start gap-2 md:justify-end">
          <Button asChild variant="outline" size="sm">
            <Link href="/duvet/report.html">
              <ExternalLink aria-hidden="true" />
              Open HTML
            </Link>
          </Button>
          <Button asChild variant="outline" size="sm">
            <a href="/duvet/report.json" download>
              <FileJson aria-hidden="true" />
              JSON
            </a>
          </Button>
          <Button asChild variant="outline" size="sm">
            <a href="/duvet/snapshot.txt" download>
              <FileText aria-hidden="true" />
              Snapshot
            </a>
          </Button>
        </div>
      </section>

      <section className="duvet-report-shell" aria-label="Duvet RFC compliance report">
        <iframe className="duvet-report-frame" src="/duvet/report.html" title="Duvet RFC compliance report" />
      </section>
    </main>
  );
}

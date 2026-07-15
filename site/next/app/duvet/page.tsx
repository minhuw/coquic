import type { Metadata } from 'next';
import Link from 'next/link';
import { ExternalLink, FileJson, FileText } from 'lucide-react';

import { DuvetReportFrame } from '@/components/duvet-report-frame';
import { PageHeader } from '@/components/page-header';
import { Button } from '@/components/ui/button';

export const metadata: Metadata = {
  title: 'CoQUIC Duvet RFC Compliance',
  other: {
    'coquic-duvet-marker': 'coquic-duvet-report-v1',
  },
};

export default function DuvetPage() {
  return (
    <main className="coquic-page compliance-page">
      <PageHeader
        eyebrow="RFC traceability"
        title="CoQUIC Duvet Report"
        description={
          <p>
            Duvet maps extracted RFC requirements to implementation and test annotations in the CoQUIC source tree.
          </p>
        }
        actions={
          <div className="compliance-actions">
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
        }
        variant="evidence"
      />

      <section className="duvet-report-shell" aria-label="Duvet RFC compliance report">
        <DuvetReportFrame />
      </section>
    </main>
  );
}

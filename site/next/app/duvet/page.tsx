import type { Metadata } from 'next';
import Link from 'next/link';
import { ExternalLink, FileJson, FileText } from 'lucide-react';

import { ComplianceAction, CompliancePage, complianceStyles as styles } from '@/components/compliance';
import { DuvetReportFrame } from '@/components/duvet-report-frame';

export const metadata: Metadata = {
  title: 'CoQUIC Duvet RFC Compliance',
  other: {
    'coquic-duvet-marker': 'coquic-duvet-report-v1',
  },
};

export default function DuvetPage() {
  return (
    <CompliancePage
        eyebrow="RFC traceability"
        title="CoQUIC Duvet Report"
        description={
          <p>
            Duvet maps extracted RFC requirements to implementation and test annotations in the CoQUIC source tree.
          </p>
        }
        actions={
          <>
            <ComplianceAction asChild variant="outline" size="sm">
              <Link href="/duvet/report.html">
                <ExternalLink aria-hidden="true" />
                Open HTML
              </Link>
            </ComplianceAction>
            <ComplianceAction asChild variant="outline" size="sm">
              <a href="/duvet/report.json" download>
                <FileJson aria-hidden="true" />
                JSON
              </a>
            </ComplianceAction>
            <ComplianceAction asChild variant="outline" size="sm">
              <a href="/duvet/snapshot.txt" download>
                <FileText aria-hidden="true" />
                Snapshot
              </a>
            </ComplianceAction>
          </>
        }
      >
      <section className={styles.duvetReportShell} aria-label="Duvet RFC compliance report">
        <DuvetReportFrame />
      </section>
    </CompliancePage>
  );
}

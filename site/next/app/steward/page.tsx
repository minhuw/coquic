import type { Metadata } from 'next';

import { PageHeader } from '@/components/page-header';
import { StewardDashboardLive } from '@/components/steward/dashboard';

export const metadata: Metadata = {
  title: 'CoQUIC Steward',
  other: {
    'coquic-steward-marker': 'coquic-steward-public-v1',
  },
};

export default function StewardPage() {
  return (
    <main className="coquic-page steward-dashboard-page steward-dashboard-route" data-steward-surface="dashboard">
      <PageHeader
        description="A read-only public publication of Steward runtime state, work evidence, and current freshness."
        eyebrow="public operations"
        title="CoQUIC Steward"
        variant="operations"
      />
      <section aria-label="Steward dashboard" className="steward-dashboard-page-content" data-steward-root="dashboard">
        <StewardDashboardLive />
      </section>
    </main>
  );
}

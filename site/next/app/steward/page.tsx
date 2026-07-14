import type { Metadata } from 'next';

import { StewardDashboardLive } from '@/components/steward-public';

export const metadata: Metadata = {
  title: 'CoQUIC Steward',
  other: {
    'coquic-steward-marker': 'coquic-steward-public-v1',
  },
};

export default function StewardPage() {
  return (
    <main className="coquic-page steward-public-page">
      <section className="mt-4">
        <StewardDashboardLive />
      </section>
    </main>
  );
}

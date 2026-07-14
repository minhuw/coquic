import type { Metadata } from 'next';

import { StewardPlannerLive } from '@/components/steward-planner';

export const metadata: Metadata = {
  title: 'Planner history | CoQUIC Steward',
};

export default function StewardPlannerPage() {
  return (
    <main className="coquic-page steward-public-page">
      <StewardPlannerLive />
    </main>
  );
}

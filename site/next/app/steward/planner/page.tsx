import type { Metadata } from 'next';

import { StewardPlannerLive } from '@/components/steward-planner';

export const metadata: Metadata = {
  title: 'Planner history | CoQUIC Steward',
};

export default function StewardPlannerPage() {
  return (
    <main className="steward-planner-route mx-auto w-full max-w-[1340px] px-3 pb-10 sm:px-[18px] lg:px-6 lg:pb-14 max-[680px]:px-3 max-[680px]:pb-8" data-steward-surface="planner">
      <StewardPlannerLive />
    </main>
  );
}

import type { Metadata } from 'next';
import { notFound } from 'next/navigation';

import { StewardTaskDetailLive } from '@/components/steward-public';

type StewardTaskPageProps = {
  params: Promise<{ taskId: string }>;
};

export async function generateMetadata({ params }: StewardTaskPageProps): Promise<Metadata> {
  const { taskId } = await params;
  return {
    title: `${taskId} | CoQUIC Steward`,
  };
}

export default async function StewardTaskPage({ params }: StewardTaskPageProps) {
  const { taskId } = await params;
  if (!/^task-\d{14}-[a-f0-9]{8}$/.test(taskId)) notFound();
  return (
    <main className="steward-task-route mx-auto w-full max-w-[1340px] px-3 pb-10 sm:px-[18px] lg:px-6 lg:pb-14 max-[680px]:px-3 max-[680px]:pb-8" data-steward-surface="task">
      <StewardTaskDetailLive taskId={taskId} />
    </main>
  );
}

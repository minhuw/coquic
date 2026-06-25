import type { Metadata } from 'next';
import { notFound } from 'next/navigation';

import { DemoNav } from '@/components/demo-nav';
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
    <main className="coquic-page steward-public-page">
      <DemoNav active="steward" />
      <StewardTaskDetailLive taskId={taskId} />
    </main>
  );
}

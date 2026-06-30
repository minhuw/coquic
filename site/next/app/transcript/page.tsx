import type { Metadata } from 'next';

import { DemoNav } from '@/components/demo-nav';
import { TranscriptDataset } from './transcript-dataset';

export const metadata: Metadata = {
  title: 'CoQUIC Transcript Dataset',
  description: 'Public Codex development transcripts for the CoQUIC project.',
  other: {
    'coquic-transcript-marker': 'coquic-transcript-dataset-v1',
  },
};

export default function TranscriptPage() {
  return (
    <main className="coquic-page transcript-page">
      <DemoNav active="dataset" />
      <TranscriptDataset />
    </main>
  );
}

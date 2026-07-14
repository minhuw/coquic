import type { Metadata } from 'next';
import { Suspense } from 'react';

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
      <Suspense fallback={<div className="transcript-route-loading">Loading transcript dataset</div>}>
        <TranscriptDataset />
      </Suspense>
    </main>
  );
}

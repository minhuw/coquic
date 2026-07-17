import type { Metadata } from 'next';
import { Suspense } from 'react';

import { cn } from '@/lib/utils';

import { TranscriptDataset } from './transcript-dataset';
import styles from './transcript.module.css';

export const metadata: Metadata = {
  title: 'CoQUIC Transcript Dataset',
  description: 'Public Codex development transcripts for the CoQUIC project.',
  other: {
    'coquic-transcript-marker': 'coquic-transcript-dataset-v1',
  },
};

export default function TranscriptPage() {
  return (
    <main className={cn('coquic-page', styles['transcript-page'])}>
      <Suspense fallback={<div className={styles['transcript-route-loading']}>Loading transcript dataset</div>}>
        <TranscriptDataset />
      </Suspense>
    </main>
  );
}

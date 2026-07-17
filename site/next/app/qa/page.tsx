import type { Metadata } from 'next';

import { PageHeader } from '@/components/page-header';

import { QaClient } from './qa-client';
import styles from './qa.module.css';

export const metadata: Metadata = {
  title: 'CoQUIC QUIC QA',
  other: {
    'coquic-qa-marker': 'coquic-rag-qa-v1',
  },
};

export default function QaPage() {
  return (
    <main className={`coquic-page ${styles.root}`} data-qa-root="true">
      <PageHeader className={styles['page-header']} eyebrow="QUIC RAG" title="CoQUIC Specification QA" variant="tool" />
      <QaClient />
    </main>
  );
}

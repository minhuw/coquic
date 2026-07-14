import type { Metadata } from 'next';

import { PageHeader } from '@/components/page-header';

import { QaClient } from './qa-client';

export const metadata: Metadata = {
  title: 'CoQUIC QUIC QA',
  other: {
    'coquic-qa-marker': 'coquic-rag-qa-v1',
  },
};

export default function QaPage() {
  return (
    <main className="coquic-page qa-page">
      <PageHeader className="qa-page-header" eyebrow="QUIC RAG" title="CoQUIC Specification QA" />
      <QaClient />
    </main>
  );
}

import type { Metadata } from 'next';

import { DemoNav } from '@/components/demo-nav';
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
    <main className="coquic-page">
      <DemoNav active="qa" />

      <section className="py-6 lg:py-7">
        <PageHeader eyebrow="QUIC RAG" title="CoQUIC Specification QA" />
      </section>

      <QaClient />
    </main>
  );
}

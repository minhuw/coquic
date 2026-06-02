import type { Metadata } from 'next';
import { notFound } from 'next/navigation';

import { DocsView } from '@/components/docs/docs-view';
import { getDocPage } from '@/lib/docs';

export const metadata: Metadata = {
  title: 'CoQUIC Documentation',
  description: 'CoQUIC project and public C++ API documentation.',
};

export default function DocsIndexPage() {
  const page = getDocPage([]);
  if (!page) notFound();

  return <DocsView page={page} />;
}

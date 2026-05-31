import type { Metadata } from 'next';
import { notFound } from 'next/navigation';

import { DocsView } from '@/components/docs/docs-view';
import { getDocPage, getStaticDocSlugs } from '@/lib/docs';

type DocsPageProps = {
  params: Promise<{ slug: string[] }>;
};

export function generateStaticParams() {
  return getStaticDocSlugs();
}

export async function generateMetadata({ params }: DocsPageProps): Promise<Metadata> {
  const { slug } = await params;
  const page = getDocPage(slug);
  if (!page) {
    return {
      title: 'CoQUIC Documentation',
    };
  }

  return {
    title: `${page.title} | CoQUIC Documentation`,
    description: page.description,
  };
}

export default async function DocsSlugPage({ params }: DocsPageProps) {
  const { slug } = await params;
  const page = getDocPage(slug);
  if (!page) notFound();

  return <DocsView page={page} />;
}

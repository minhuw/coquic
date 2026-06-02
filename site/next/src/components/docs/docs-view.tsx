import Link from 'next/link';
import { Fragment } from 'react';

import { DemoNav } from '@/components/demo-nav';
import { Markdown } from '@/components/docs/markdown';
import { PageHeader } from '@/components/page-header';
import { getDocNavItems, type DocPage } from '@/lib/docs';

type DocsViewProps = {
  page: DocPage;
};

export async function DocsView({ page }: DocsViewProps) {
  const navItems = getDocNavItems();

  return (
    <main className="coquic-page">
      <DemoNav active="docs" />
      <PageHeader eyebrow="project documentation" title={page.title} />

      <section className="docs-layout" aria-label="CoQUIC documentation">
        <aside className="docs-sidebar" aria-label="Documentation pages">
          <div className="docs-sidebar-head">
            <span>Docs</span>
            <strong>CoQUIC</strong>
          </div>
          <nav>
            {navItems.map((item, index) => (
              <Fragment key={item.href}>
                {item.section !== navItems[index - 1]?.section ? <span className="docs-nav-section">{item.section}</span> : null}
                <Link
                  className={`docs-nav-link${item.level === 1 ? ' docs-nav-link-nested' : ''}`}
                  href={item.href}
                  aria-current={item.href === page.href ? 'page' : undefined}
                >
                  {item.label}
                </Link>
              </Fragment>
            ))}
          </nav>
        </aside>

        <article className="docs-article">
          {await Markdown({ markdown: page.markdown, currentSlug: page.slug, skipFirstH1: true })}
        </article>
      </section>
    </main>
  );
}

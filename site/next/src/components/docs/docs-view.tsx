import Link from 'next/link';
import { Fragment } from 'react';
import { BookOpen, X } from 'lucide-react';

import { Markdown } from '@/components/docs/markdown';
import { PageHeader } from '@/components/page-header';
import { Dialog, DialogClose, DialogContent, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { getDocNavItems, type DocPage } from '@/lib/docs';

type DocsViewProps = {
  page: DocPage;
};

export async function DocsView({ page }: DocsViewProps) {
  const navItems = getDocNavItems();

  return (
    <main className="coquic-page docs-page">
      <PageHeader
        className="docs-page-header"
        containerClassName="docs-page-header__container"
        description={page.description}
        eyebrow="project documentation"
        title={page.title}
        actions={<DocsMobileNavigation currentHref={page.href} navItems={navItems} />}
      />

      <section className="docs-layout" aria-label="CoQUIC documentation">
        <aside className="docs-sidebar" aria-label="Documentation pages">
          <div className="docs-sidebar-head">
            <span>Docs</span>
            <strong>CoQUIC</strong>
          </div>
          <nav aria-label="Documentation pages">
            <DocsNavLinks currentHref={page.href} navItems={navItems} />
          </nav>
        </aside>

        <article className="docs-article">
          {await Markdown({ markdown: page.markdown, currentSlug: page.slug, skipFirstH1: true })}
        </article>
      </section>
    </main>
  );
}

function DocsMobileNavigation({ currentHref, navItems }: { currentHref: string; navItems: ReturnType<typeof getDocNavItems> }) {
  return (
    <div className="docs-mobile-navigation">
      <Dialog>
        <DialogTrigger asChild>
          <button className="docs-mobile-navigation__trigger" type="button">
            <BookOpen aria-hidden="true" />
            <span>Browse documentation</span>
          </button>
        </DialogTrigger>
        <DialogContent className="docs-page docs-mobile-drawer" aria-describedby={undefined}>
          <div className="docs-mobile-drawer__header">
            <DialogTitle>Documentation pages</DialogTitle>
            <DialogClose className="docs-mobile-drawer__close" aria-label="Close documentation">
              <X aria-hidden="true" />
            </DialogClose>
          </div>
          <nav aria-label="Documentation pages" className="docs-mobile-drawer__navigation">
            <DocsNavLinks currentHref={currentHref} drawer navItems={navItems} />
          </nav>
        </DialogContent>
      </Dialog>
    </div>
  );
}

function DocsNavLinks({
  currentHref,
  drawer = false,
  navItems,
}: {
  currentHref: string;
  drawer?: boolean;
  navItems: ReturnType<typeof getDocNavItems>;
}) {
  return navItems.map((item, index) => {
    const link = (
      <Link
        className={`docs-nav-link${item.level === 1 ? ' docs-nav-link-nested' : ''}`}
        href={item.href}
        aria-current={item.href === currentHref ? 'page' : undefined}
      >
        {item.label}
      </Link>
    );

    return (
      <Fragment key={item.href}>
        {item.section !== navItems[index - 1]?.section ? <span className="docs-nav-section">{item.section}</span> : null}
        {drawer ? <DialogClose asChild>{link}</DialogClose> : link}
      </Fragment>
    );
  });
}

import Link from 'next/link';
import { Fragment } from 'react';
import { BookOpen, X } from 'lucide-react';

import { Markdown } from '@/components/docs/markdown';
import { PageHeader } from '@/components/page-header';
import { Button } from '@/components/ui/button';
import { Dialog, DialogClose, DialogContent, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { getDocNavItems, type DocPage } from '@/lib/docs';
import { cn } from '@/lib/utils';

import styles from './docs-view.module.css';

type DocsViewProps = {
  page: DocPage;
};

export async function DocsView({ page }: DocsViewProps) {
  const navItems = getDocNavItems();

  return (
    <main className="docs-page mx-auto w-full max-w-[1340px] px-3 pb-10 sm:px-[18px] lg:px-6 lg:pb-14 max-[680px]:px-3 max-[680px]:pb-8">
      <PageHeader
        className={styles.header}
        containerClassName={styles.headerContainer}
        description={page.description}
        eyebrow="project documentation"
        title={page.title}
        actions={<DocsMobileNavigation currentHref={page.href} navItems={navItems} />}
        variant="editorial"
      />

      <section className={styles.layout} aria-label="CoQUIC documentation">
        <aside className={styles.sidebar} aria-label="Documentation pages">
          <div className={styles.sidebarHead}>
            <span>Docs</span>
            <strong>CoQUIC</strong>
          </div>
          <nav aria-label="Documentation pages">
            <DocsNavLinks currentHref={page.href} navItems={navItems} />
          </nav>
        </aside>

        <article className={styles.article}>
          {await Markdown({ markdown: page.markdown, currentSlug: page.slug, skipFirstH1: true })}
        </article>
      </section>
    </main>
  );
}

function DocsMobileNavigation({ currentHref, navItems }: { currentHref: string; navItems: ReturnType<typeof getDocNavItems> }) {
  return (
    <div className={styles.mobileNavigation}>
      <Dialog>
        <DialogTrigger asChild>
          <Button className={styles.mobileTrigger} type="button" variant="outline">
            <BookOpen aria-hidden="true" />
            <span>Browse documentation</span>
          </Button>
        </DialogTrigger>
        <DialogContent className={styles.mobileDrawer} aria-describedby={undefined}>
          <div className={styles.drawerHeader}>
            <DialogTitle>Documentation pages</DialogTitle>
            <DialogClose asChild>
              <Button className={styles.drawerClose} aria-label="Close documentation" size="icon" type="button" variant="ghost">
                <X aria-hidden="true" />
              </Button>
            </DialogClose>
          </div>
          <nav aria-label="Documentation pages" className={styles.drawerNavigation}>
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
        className={cn(
          styles.navLink,
          'docs-nav-link',
          item.level === 1 && styles.navLinkNested,
        )}
        href={item.href}
        aria-current={item.href === currentHref ? 'page' : undefined}
      >
        {item.label}
      </Link>
    );

    return (
      <Fragment key={item.href}>
        {item.section !== navItems[index - 1]?.section ? <span className={styles.navSection}>{item.section}</span> : null}
        {drawer ? <DialogClose asChild>{link}</DialogClose> : link}
      </Fragment>
    );
  });
}

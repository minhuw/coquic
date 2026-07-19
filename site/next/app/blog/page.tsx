import type { Metadata } from 'next';
import Link from 'next/link';
import { ArrowRight } from 'lucide-react';

import { PageHeader } from '@/components/page-header';
import { formatBlogDate, getBlogPosts } from '@/lib/blog';
import styles from '@/components/blog/blog.module.css';
import { cn } from '@/lib/utils';

export const metadata: Metadata = {
  title: 'CoQUIC Blog',
  description: 'CoQUIC project notes, implementation updates, interop findings, and benchmark observations.',
};

export default function BlogIndexPage() {
  const posts = getBlogPosts();

  return (
    <main className={styles.page}>
      <PageHeader
        className={styles.indexHeader}
        eyebrow="project blog"
        title="CoQUIC Blog"
        variant="editorial"
      />

      <section className={styles.list} aria-label="Blog posts">
        {posts.length ? (
          posts.map((post) => (
            <article className={cn(styles.row, 'blog-row')} key={post.slug}>
              <Link className={styles.rowLink} href={`/blog/${post.slug}`}>
                <div className={styles.rowMain}>
                  <div className={cn(styles.rowMeta, 'blog-row-meta')}>
                    <time className={styles.metaDate} dateTime={post.date}>
                      {formatBlogDate(post.date)}
                    </time>
                    <span className={styles.metaUnit}>{post.readingMinutes} min read</span>
                    <span className={styles.metaPerson}>{post.author}</span>
                    {post.writtenBy ? <span className={styles.metaAttribution}>Written by {post.writtenBy}</span> : null}
                    {post.polishedBy ? <span className={styles.metaAttribution}>Polished by {post.polishedBy}</span> : null}
                  </div>
                  <h2 className={styles.rowTitle}>{post.title}</h2>
                  <p className={styles.rowDescription}>{post.description}</p>
                  <span className={styles.rowFoot}>
                    <span className={cn(styles.tags, 'blog-tags')}>
                      {post.tags.map((tag) => (
                        <span className={styles.tag} key={tag}>{tag}</span>
                      ))}
                    </span>
                    <span className={cn(styles.rowCta, 'blog-row-cta')}>
                      Read article
                      <ArrowRight aria-hidden="true" />
                    </span>
                  </span>
                </div>
              </Link>
            </article>
          ))
        ) : (
          <p className={styles.emptyState}>No blog posts have been published yet.</p>
        )}
      </section>
    </main>
  );
}

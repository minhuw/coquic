import type { Metadata } from 'next';
import Link from 'next/link';
import { ArrowRight } from 'lucide-react';

import { PageHeader } from '@/components/page-header';
import { formatBlogDate, getBlogPosts } from '@/lib/blog';

export const metadata: Metadata = {
  title: 'CoQUIC Blog',
  description: 'CoQUIC project notes, implementation updates, interop findings, and benchmark observations.',
};

export default function BlogIndexPage() {
  const posts = getBlogPosts();

  return (
    <main className="coquic-page">
      <PageHeader
        containerClassName="blog-page-header__container"
        eyebrow="project blog"
        title="CoQUIC Blog"
        variant="editorial"
      />

      <section className="blog-list" aria-label="Blog posts">
        {posts.length ? (
          posts.map((post) => (
            <article className="blog-row" key={post.slug}>
              <Link className="blog-row-link" href={`/blog/${post.slug}`}>
                <div className="blog-row-main">
                  <div className="blog-row-meta">
                    <time className="blog-meta-date" dateTime={post.date}>
                      {formatBlogDate(post.date)}
                    </time>
                    <span className="blog-meta-unit">{post.readingMinutes} min read</span>
                    <span className="blog-meta-person">{post.author}</span>
                    {post.writtenBy ? <span className="blog-meta-attribution">Written by {post.writtenBy}</span> : null}
                    {post.polishedBy ? <span className="blog-meta-attribution">Polished by {post.polishedBy}</span> : null}
                  </div>
                  <h2>{post.title}</h2>
                  <p>{post.description}</p>
                  <span className="blog-row-foot">
                    <span className="blog-tags">
                      {post.tags.map((tag) => (
                        <span key={tag}>{tag}</span>
                      ))}
                    </span>
                    <span className="blog-row-cta">
                      Read article
                      <ArrowRight aria-hidden="true" />
                    </span>
                  </span>
                </div>
              </Link>
            </article>
          ))
        ) : (
          <p className="empty-state">No blog posts have been published yet.</p>
        )}
      </section>
    </main>
  );
}

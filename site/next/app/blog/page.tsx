import type { Metadata } from 'next';
import Link from 'next/link';
import { ArrowRight } from 'lucide-react';

import { DemoNav } from '@/components/demo-nav';
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
      <DemoNav active="blog" />
      <PageHeader eyebrow="project blog" title="CoQUIC Blog" />

      <section className="blog-list" aria-label="Blog posts">
        {posts.length ? (
          posts.map((post) => (
            <article className="blog-card" key={post.slug}>
              <Link className="blog-card-link" href={`/blog/${post.slug}`}>
                <span className="blog-card-meta">
                  <time dateTime={post.date}>{formatBlogDate(post.date)}</time>
                  <span>{post.readingMinutes} min read</span>
                </span>
                <h2>{post.title}</h2>
                <p>{post.description}</p>
                <span className="blog-card-foot">
                  <span className="blog-tags">
                    {post.tags.map((tag) => (
                      <span key={tag}>{tag}</span>
                    ))}
                  </span>
                  <ArrowRight aria-hidden="true" />
                </span>
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

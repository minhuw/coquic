import type { Metadata } from 'next';
import Link from 'next/link';
import { notFound } from 'next/navigation';
import { ArrowLeft } from 'lucide-react';

import { BlogLanguageProvider, BlogLanguageTabs } from '@/components/blog/blog-language-switcher';
import { BlogPostContent } from '@/components/blog/blog-post-content';
import { formatBlogDate, getBlogPost, getStaticBlogSlugs } from '@/lib/blog';

type BlogPostPageProps = {
  params: Promise<{ slug: string }>;
};

export function generateStaticParams() {
  return getStaticBlogSlugs();
}

export async function generateMetadata({ params }: BlogPostPageProps): Promise<Metadata> {
  const { slug } = await params;
  const post = getBlogPost(slug);
  if (!post) {
    return {
      title: 'CoQUIC Blog',
    };
  }

  return {
    title: `${post.title} | CoQUIC Blog`,
    description: post.description,
  };
}

export default async function BlogPostPage({ params }: BlogPostPageProps) {
  const { slug } = await params;
  const post = getBlogPost(slug);
  if (!post) notFound();

  return (
    <main className="coquic-page">
      <BlogLanguageProvider>
        <article className="blog-post">
          <Link className="blog-back-link" href="/blog">
            <ArrowLeft aria-hidden="true" />
            Blog
          </Link>
          <header className="blog-post-header">
            <div className="blog-post-meta">
              <time className="blog-post-meta-date" dateTime={post.date}>
                {formatBlogDate(post.date)}
              </time>
              <span className="blog-post-meta-unit">{post.readingMinutes} min read</span>
              <span className="blog-post-meta-person">{post.author}</span>
              {post.writtenBy ? <span className="blog-post-meta-attribution">Written by {post.writtenBy}</span> : null}
              {post.polishedBy ? <span className="blog-post-meta-attribution">Polished by {post.polishedBy}</span> : null}
            </div>
            <h1>{post.title}</h1>
            <p>{post.description}</p>
            <div className="blog-post-actions">
              {post.tags.length ? (
                <span className="blog-tags">
                  {post.tags.map((tag) => (
                    <span key={tag}>{tag}</span>
                  ))}
                </span>
              ) : null}
              <BlogLanguageTabs />
            </div>
          </header>
          <BlogPostContent post={post} />
        </article>
      </BlogLanguageProvider>
    </main>
  );
}

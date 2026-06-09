import type { Metadata } from 'next';
import Link from 'next/link';
import { notFound } from 'next/navigation';
import { ArrowLeft } from 'lucide-react';

import { BlogLanguageProvider, BlogLanguageTabs } from '@/components/blog/blog-language-switcher';
import { BlogPostContent } from '@/components/blog/blog-post-content';
import { DemoNav } from '@/components/demo-nav';
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
      <DemoNav active="blog" />

      <BlogLanguageProvider>
        <article className="blog-post">
          <Link className="blog-back-link" href="/blog">
            <ArrowLeft aria-hidden="true" />
            Blog
          </Link>
          <header className="blog-post-header">
            <span className="blog-card-meta">
              <time dateTime={post.date}>{formatBlogDate(post.date)}</time>
              <span>{post.readingMinutes} min read</span>
              <span>{post.author}</span>
            </span>
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
          <div className="blog-post-body">
            <BlogPostContent post={post} />
          </div>
        </article>
      </BlogLanguageProvider>
    </main>
  );
}

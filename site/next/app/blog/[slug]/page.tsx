import type { Metadata } from 'next';
import Link from 'next/link';
import { notFound } from 'next/navigation';
import { ArrowLeft } from 'lucide-react';

import { BlogLanguageProvider, BlogLanguageTabs } from '@/components/blog/blog-language-switcher';
import { BlogPostContent } from '@/components/blog/blog-post-content';
import { formatBlogDate, getBlogPost, getStaticBlogSlugs } from '@/lib/blog';
import styles from '@/components/blog/blog.module.css';
import { cn } from '@/lib/utils';

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
    <main className={styles.page}>
      <BlogLanguageProvider>
        <article className={cn(styles.post, 'blog-post')}>
          <Link className={styles.backLink} href="/blog">
            <ArrowLeft aria-hidden="true" />
            Blog
          </Link>
          <header className={cn(styles.postHeader, 'blog-post-header')}>
            <div className={styles.postMeta}>
              <time className={styles.metaDate} dateTime={post.date}>
                {formatBlogDate(post.date)}
              </time>
              <span className={styles.metaUnit}>{post.readingMinutes} min read</span>
              <span className={styles.metaPerson}>{post.author}</span>
              {post.writtenBy ? <span className={styles.metaAttribution}>Written by {post.writtenBy}</span> : null}
              {post.polishedBy ? <span className={styles.metaAttribution}>Polished by {post.polishedBy}</span> : null}
            </div>
            <h1 className={styles.postTitle}>{post.title}</h1>
            <p className={styles.postDescription}>{post.description}</p>
            <div className={cn(styles.postActions, 'blog-post-actions')}>
              {post.tags.length ? (
                <span className={cn(styles.tags, 'blog-tags')}>
                  {post.tags.map((tag) => (
                    <span className={styles.tag} key={tag}>{tag}</span>
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

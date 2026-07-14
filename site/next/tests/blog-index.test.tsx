import { cleanup, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const fixture = vi.hoisted(() => ({
  posts: [] as Array<import('@/lib/blog').BlogPostMeta>,
}));

vi.mock('@/lib/blog', async () => {
  const actual = await vi.importActual<typeof import('@/lib/blog')>('@/lib/blog');
  return {
    ...actual,
    getBlogPosts: vi.fn(() => fixture.posts),
  };
});

import BlogIndexPage from '@app/blog/page';

afterEach(cleanup);

describe('blog index characterization', () => {
  beforeEach(async () => {
    const actual = await vi.importActual<typeof import('@/lib/blog')>('@/lib/blog');
    fixture.posts = actual.getBlogPosts();
  });

  it('parses both static posts in descending date order with factual metadata', async () => {
    const actual = await vi.importActual<typeof import('@/lib/blog')>('@/lib/blog');
    const posts = actual.getBlogPosts();

    expect(posts.map((post) => post.slug)).toEqual(['coquic-steward', 'why-coquic']);
    expect(actual.getStaticBlogSlugs()).toEqual([
      { slug: 'coquic-steward' },
      { slug: 'why-coquic' },
    ]);
    expect(posts).toEqual([
      expect.objectContaining({
        slug: 'coquic-steward',
        title: 'CoQUIC Steward: Letting an Agent Maintain the Repository',
        description: expect.stringContaining('How Steward turns CI failures'),
        date: '2026-07-02',
        author: 'Minhu Wang',
        writtenBy: 'Claude Fable 5',
        polishedBy: '',
        tags: ['AI', 'agents', 'engineering'],
        readingMinutes: expect.any(Number),
      }),
      expect.objectContaining({
        slug: 'why-coquic',
        title: 'Why CoQUIC?',
        date: '2026-06-09',
        author: 'Minhu Wang',
        writtenBy: '',
        polishedBy: 'GPT',
        tags: ['QUIC', 'AI', 'engineering'],
        readingMinutes: expect.any(Number),
      }),
    ]);
  });

  it('renders ordered post links, date, reading time, author, attribution, and tags', () => {
    render(BlogIndexPage());

    const articles = screen.getAllByRole('article');
    expect(articles).toHaveLength(fixture.posts.length);
    expect(articles.map((article) => article.querySelector('h2')?.textContent)).toEqual(
      fixture.posts.map((post) => post.title),
    );

    for (const [index, post] of fixture.posts.entries()) {
      const article = articles[index];
      expect(article.querySelector('a')).toHaveAttribute('href', `/blog/${post.slug}`);
      expect(article).toHaveTextContent(post.title);
      expect(article).toHaveTextContent(post.description);
      expect(article).toHaveTextContent(`${post.readingMinutes} min read`);
      expect(article).toHaveTextContent(post.author);
      expect(article).toHaveTextContent(post.tags.join(''));
      expect(article.querySelector('time')).toHaveAttribute('dateTime', post.date);
      if (post.writtenBy) expect(article).toHaveTextContent(`Written by ${post.writtenBy}`);
      if (post.polishedBy) expect(article).toHaveTextContent(`Polished by ${post.polishedBy}`);
    }
  });

  it('keeps the empty state attached to the list region', () => {
    fixture.posts = [];

    render(BlogIndexPage());

    expect(screen.getByRole('region', { name: 'Blog posts' })).toContainElement(
      screen.getByText('No blog posts have been published yet.'),
    );
    expect(screen.queryByRole('article')).not.toBeInTheDocument();
  });
});

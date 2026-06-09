import { existsSync, readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';

export type BlogPostMeta = {
  slug: string;
  format: BlogPostFormat;
  title: string;
  description: string;
  date: string;
  author: string;
  tags: string[];
  readingMinutes: number;
};

export type BlogPost = BlogPostMeta & {
  markdown: string;
};

export type BlogPostFormat = 'md' | 'mdx';

type Frontmatter = Record<string, string>;

export function getBlogPosts(): BlogPostMeta[] {
  if (!existsSync(blogDirectory())) return [];

  return readdirSync(blogDirectory(), { withFileTypes: true })
    .filter((entry) => entry.isFile() && isBlogFile(entry.name))
    .map((entry) => readBlogPost(entry.name))
    .filter((post): post is BlogPost => Boolean(post))
    .sort((left, right) => right.date.localeCompare(left.date))
    .map(({ markdown: _markdown, ...meta }) => meta);
}

export function getStaticBlogSlugs() {
  return getBlogPosts().map((post) => ({ slug: post.slug }));
}

export function getBlogPost(slug: string): BlogPost | null {
  if (!isBlogSlug(slug)) return null;
  return readBlogPost(`${slug}.md`) ?? readBlogPost(`${slug}.mdx`);
}

export function hrefForBlogLink(href: string) {
  if (/^[a-z][a-z0-9+.-]*:/i.test(href) || href.startsWith('#') || href.startsWith('/')) {
    return href;
  }

  if (!href.endsWith('.md')) {
    if (href.endsWith('.mdx')) {
      const slug = href
        .replace(/\.mdx$/, '')
        .split('/')
        .filter(Boolean)
        .at(-1);
      return slug && isBlogSlug(slug) ? `/blog/${slug}` : href;
    }

    return href;
  }

  const slug = href
    .replace(/\.md$/, '')
    .split('/')
    .filter(Boolean)
    .at(-1);
  return slug && isBlogSlug(slug) ? `/blog/${slug}` : href;
}

export function formatBlogDate(date: string) {
  return new Intl.DateTimeFormat('en', {
    dateStyle: 'medium',
    timeZone: 'UTC',
  }).format(new Date(`${date}T00:00:00Z`));
}

function readBlogPost(fileName: string): BlogPost | null {
  const slug = fileName.replace(/\.mdx?$/, '');
  if (!isBlogSlug(slug)) return null;

  const filePath = path.join(blogDirectory(), fileName);
  if (!existsSync(filePath)) return null;

  const raw = readFileSync(filePath, 'utf-8');
  const { frontmatter, markdown } = splitFrontmatter(raw);
  const title = frontmatter.title || extractTitle(markdown);
  if (!title) return null;

  return {
    slug,
    format: fileName.endsWith('.mdx') ? 'mdx' : 'md',
    title,
    description: frontmatter.description || extractDescription(markdown),
    date: frontmatter.date || '1970-01-01',
    author: frontmatter.author || 'CoQUIC',
    tags: parseTags(frontmatter.tags),
    readingMinutes: estimateReadingMinutes(markdown),
    markdown,
  };
}

function splitFrontmatter(raw: string): { frontmatter: Frontmatter; markdown: string } {
  const normalized = raw.replace(/\r\n/g, '\n');
  if (!normalized.startsWith('---\n')) {
    return { frontmatter: {}, markdown: normalized };
  }

  const end = normalized.indexOf('\n---\n', 4);
  if (end < 0) {
    return { frontmatter: {}, markdown: normalized };
  }

  const frontmatter = normalized
    .slice(4, end)
    .split('\n')
    .reduce<Frontmatter>((fields, line) => {
      const match = line.match(/^([A-Za-z][A-Za-z0-9_-]*):\s*(.*)$/);
      if (!match) return fields;
      fields[match[1]] = stripQuotes(match[2].trim());
      return fields;
    }, {});

  return {
    frontmatter,
    markdown: normalized.slice(end + 5).trimStart(),
  };
}

function stripQuotes(value: string) {
  return value.replace(/^["']|["']$/g, '');
}

function parseTags(value = '') {
  return value
    .split(',')
    .map((tag) => tag.trim())
    .filter(Boolean);
}

function estimateReadingMinutes(markdown: string) {
  const words = markdown
    .replace(/```[\s\S]*?```/g, ' ')
    .replace(/[#*_`[\]().,:;!?/\\-]+/g, ' ')
    .split(/\s+/)
    .filter(Boolean).length;
  return Math.max(1, Math.ceil(words / 220));
}

function extractTitle(markdown: string) {
  return markdown.match(/^#\s+(.+)$/m)?.[1]?.trim() || '';
}

function extractDescription(markdown: string) {
  const paragraph = markdown
    .replace(/\r\n/g, '\n')
    .split('\n')
    .find((line) => {
      const trimmed = line.trim();
      return trimmed.length > 0 && !trimmed.startsWith('#') && !trimmed.startsWith('```') && !trimmed.startsWith('- ');
    });
  return paragraph?.trim() || 'CoQUIC project blog post.';
}

function isBlogSlug(slug: string) {
  return /^[a-z0-9-]+$/.test(slug);
}

function isBlogFile(fileName: string) {
  return /^[a-z0-9-]+\.mdx?$/.test(fileName);
}

function blogDirectory() {
  return path.join(process.cwd(), 'content', 'blog');
}

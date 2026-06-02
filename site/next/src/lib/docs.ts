import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';

import { docItems, type DocNavItem, type DocSlug } from '@/lib/doc-items';

export type DocPage = DocNavItem & {
  title: string;
  description: string;
  markdown: string;
};

export function getDocNavItems() {
  return docItems;
}

export function getStaticDocSlugs() {
  return docItems.filter((item) => item.slug.length > 0).map((item) => ({ slug: item.slug }));
}

export function getDocPage(slug: readonly string[] = []): DocPage | null {
  const normalizedSlug = normalizeSlug(slug);
  if (!normalizedSlug) return null;

  const item = docItems.find((candidate) => sameSlug(candidate.slug, normalizedSlug));
  if (!item) return null;

  const markdown = readFileSync(path.join(findRepoRoot(), 'docs', item.file), 'utf-8');
  return {
    ...item,
    title: extractTitle(markdown) ?? item.label,
    description: extractDescription(markdown),
    markdown,
  };
}

export function hrefForDocLink(href: string, currentSlug: readonly string[]) {
  if (/^[a-z][a-z0-9+.-]*:/i.test(href) || href.startsWith('#') || href.startsWith('/')) {
    return href;
  }

  if (!href.endsWith('.md')) {
    return href;
  }

  const currentDirectory = currentSlug.slice(0, -1);
  const target = href
    .replace(/\.md$/, '')
    .split('/')
    .reduce<string[]>((segments, segment) => {
      if (!segment || segment === '.') return segments;
      if (segment === '..') return segments.slice(0, -1);
      return [...segments, segment];
    }, [...currentDirectory]);

  return target.length === 0 || target.join('/') === 'README' ? '/docs' : `/docs/${target.join('/')}`;
}

function normalizeSlug(slug: readonly string[]) {
  if (slug.some((segment) => !/^[a-z0-9-]+$/.test(segment))) return null;
  return [...slug];
}

function sameSlug(left: readonly string[], right: readonly string[]) {
  return left.length === right.length && left.every((segment, index) => segment === right[index]);
}

function extractTitle(markdown: string) {
  return markdown.match(/^#\s+(.+)$/m)?.[1]?.trim();
}

function extractDescription(markdown: string) {
  const lines = markdown.replace(/\r\n/g, '\n').split('\n');
  const firstParagraph = lines.find((line) => {
    const trimmed = line.trim();
    return trimmed.length > 0 && !trimmed.startsWith('#') && !trimmed.startsWith('```') && !trimmed.startsWith('- ');
  });
  return firstParagraph?.trim() ?? 'CoQUIC project documentation.';
}

function findRepoRoot() {
  let directory = process.cwd();

  while (true) {
    if (existsSync(path.join(directory, 'build.zig')) && existsSync(path.join(directory, 'docs'))) {
      return directory;
    }

    const parent = path.dirname(directory);
    if (parent === directory) {
      throw new Error(`Unable to find CoQUIC repository root from ${process.cwd()}`);
    }
    directory = parent;
  }
}

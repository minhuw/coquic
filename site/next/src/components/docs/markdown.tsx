import Link from 'next/link';
import type React from 'react';
import { codeToHtml } from 'shiki';

import { CopyCodeButton } from '@/components/docs/copy-code-button';
import { hrefForDocLink } from '@/lib/docs';

type MarkdownBlock =
  | { type: 'heading'; depth: number; text: string }
  | { type: 'paragraph'; text: string }
  | { type: 'list'; ordered: boolean; items: string[] }
  | { type: 'code'; language: string; code: string };

type MarkdownProps = {
  markdown: string;
  currentSlug: string[];
  skipFirstH1?: boolean;
};

export async function Markdown({ markdown, currentSlug, skipFirstH1 = false }: MarkdownProps) {
  let skippedH1 = false;
  const blocks = parseMarkdown(markdown).filter((block) => {
    if (skipFirstH1 && !skippedH1 && block.type === 'heading' && block.depth === 1) {
      skippedH1 = true;
      return false;
    }
    return true;
  });

  return (
    <div className="docs-markdown">
      {blocks.map((block, index) => {
        if (block.type === 'heading') {
          const id = slugify(block.text);
          if (block.depth === 1) return <h1 key={index}>{renderInline(block.text, currentSlug)}</h1>;
          if (block.depth === 2) {
            return (
              <h2 id={id} key={index}>
                {renderInline(block.text, currentSlug)}
              </h2>
            );
          }
          return (
            <h3 id={id} key={index}>
              {renderInline(block.text, currentSlug)}
            </h3>
          );
        }

        if (block.type === 'paragraph') {
          return <p key={index}>{renderInline(block.text, currentSlug)}</p>;
        }

        if (block.type === 'list') {
          const ListTag = block.ordered ? 'ol' : 'ul';
          return (
            <ListTag key={index}>
              {block.items.map((item, itemIndex) => (
                <li key={itemIndex}>{renderInline(item, currentSlug)}</li>
              ))}
            </ListTag>
          );
        }

        return <HighlightedCode code={block.code} language={block.language} key={index} />;
      })}
    </div>
  );
}

async function HighlightedCode({ code, language }: { code: string; language: string }) {
  const html = await codeToHtml(code, {
    lang: normalizeLanguage(language),
    themes: {
      light: 'github-light',
      dark: 'github-dark',
    },
    defaultColor: false,
  });

  return (
    <div className="docs-code-block">
      <div className="docs-code-toolbar">
        <span>{language || 'text'}</span>
        <CopyCodeButton code={code} />
      </div>
      <div className="docs-code-scroll" dangerouslySetInnerHTML={{ __html: html }} />
    </div>
  );
}

function parseMarkdown(markdown: string) {
  const blocks: MarkdownBlock[] = [];
  const lines = markdown.replace(/\r\n/g, '\n').split('\n');
  let index = 0;

  const currentLine = () => lines.at(index) ?? '';

  while (index < lines.length) {
    const line = currentLine();
    const trimmed = line.trim();

    if (!trimmed) {
      index += 1;
      continue;
    }

    const fence = trimmed.match(/^```([A-Za-z0-9_+-]+)?$/);
    if (fence) {
      const codeLines: string[] = [];
      index += 1;
      while (index < lines.length && !currentLine().trim().startsWith('```')) {
        codeLines.push(currentLine());
        index += 1;
      }
      index += 1;
      blocks.push({ type: 'code', language: fence[1] || '', code: codeLines.join('\n') });
      continue;
    }

    const heading = trimmed.match(/^(#{1,3})\s+(.+)$/);
    if (heading) {
      blocks.push({ type: 'heading', depth: heading[1].length, text: heading[2].trim() });
      index += 1;
      continue;
    }

    if (/^-\s+/.test(trimmed)) {
      const items: string[] = [];
      while (index < lines.length) {
        const item = currentLine().trim().match(/^-\s+(.+)$/);
        if (!item) break;
        const parts = [item[1].trim()];
        index += 1;
        while (index < lines.length && isIndentedContinuation(currentLine()) && !/^-\s+/.test(currentLine().trim())) {
          parts.push(currentLine().trim());
          index += 1;
        }
        items.push(parts.join(' '));
      }
      blocks.push({ type: 'list', ordered: false, items });
      continue;
    }

    if (/^\d+\.\s+/.test(trimmed)) {
      const items: string[] = [];
      while (index < lines.length) {
        const item = currentLine().trim().match(/^\d+\.\s+(.+)$/);
        if (!item) break;
        const parts = [item[1].trim()];
        index += 1;
        while (index < lines.length && isIndentedContinuation(currentLine()) && !/^\d+\.\s+/.test(currentLine().trim())) {
          parts.push(currentLine().trim());
          index += 1;
        }
        items.push(parts.join(' '));
      }
      blocks.push({ type: 'list', ordered: true, items });
      continue;
    }

    const paragraph: string[] = [];
    while (index < lines.length && !isBlockStart(currentLine())) {
      paragraph.push(currentLine().trim());
      index += 1;
    }
    blocks.push({ type: 'paragraph', text: paragraph.join(' ') });
  }

  return blocks;
}

function isBlockStart(line: string) {
  const trimmed = line.trim();
  return !trimmed || /^```/.test(trimmed) || /^#{1,3}\s+/.test(trimmed) || /^-\s+/.test(trimmed) || /^\d+\.\s+/.test(trimmed);
}

function isIndentedContinuation(line: string) {
  return /^\s{2,}\S/.test(line);
}

function renderInline(text: string, currentSlug: readonly string[]) {
  const pieces: React.ReactNode[] = [];
  const tokenPattern = /(`[^`]+`|\[[^\]]+\]\([^)]+\))/g;
  let cursor = 0;

  for (const match of text.matchAll(tokenPattern)) {
    if (match.index > cursor) pieces.push(text.slice(cursor, match.index));

    const token = match[0];
    if (token.startsWith('`')) {
      pieces.push(<code key={pieces.length}>{token.slice(1, -1)}</code>);
    } else {
      const link = token.match(/^\[([^\]]+)\]\(([^)]+)\)$/);
      if (link) {
        pieces.push(
          <Link href={hrefForDocLink(link[2], currentSlug)} key={pieces.length}>
            {renderInline(link[1], currentSlug)}
          </Link>,
        );
      }
    }

    cursor = match.index + token.length;
  }

  if (cursor < text.length) pieces.push(text.slice(cursor));
  return pieces;
}

function slugify(text: string) {
  return text
    .toLowerCase()
    .replace(/`/g, '')
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '');
}

function normalizeLanguage(language: string) {
  if (!language) return 'text';
  if (language === 'sh') return 'bash';
  if (language === 'c++') return 'cpp';
  return language;
}

import Link from 'next/link';
import type React from 'react';

import { AnchoredHeading } from '@/components/editorial/anchored-heading';
import { ArticleContent } from '@/components/editorial/article-content';
import { CodeBlock } from '@/components/editorial/code-block';
import { TableRegion } from '@/components/editorial/table-region';
import { hrefForDocLink } from '@/lib/docs';

type MarkdownBlock =
  | { type: 'heading'; depth: number; text: string }
  | { type: 'paragraph'; text: string }
  | { type: 'list'; ordered: boolean; items: string[] }
  | { type: 'table'; headers: string[]; rows: string[][] }
  | { type: 'code'; language: string; code: string };

type RenderBlock = MarkdownBlock | { type: 'functionCard'; title: string; id: string; blocks: MarkdownBlock[] };

interface MarkdownProps {
  markdown: string;
  currentSlug: string[];
  skipFirstH1?: boolean;
  resolveHref?: (href: string, currentSlug: readonly string[]) => string;
}

export async function Markdown({ markdown, currentSlug, skipFirstH1 = false, resolveHref = hrefForDocLink }: MarkdownProps) {
  let skippedH1 = false;
  const parsedBlocks = parseMarkdown(markdown).filter((block) => {
    if (skipFirstH1 && !skippedH1 && block.type === 'heading' && block.depth === 1) {
      skippedH1 = true;
      return false;
    }
    return true;
  });
  const blocks = groupFunctionDocumentation(parsedBlocks);

  return (
    <ArticleContent>
      {blocks.map((block, index) => renderBlock(block, index, currentSlug, { resolveHref }))}
    </ArticleContent>
  );
}

function renderBlock(
  block: RenderBlock,
  index: number,
  currentSlug: readonly string[],
  options: { inFunctionCard?: boolean; resolveHref: (href: string, currentSlug: readonly string[]) => string },
) {
  if (block.type === 'functionCard') {
    return (
      <section className="docs-function-card" key={index}>
        <header className="docs-function-card-header">
          <AnchoredHeading className="docs-function-heading" id={block.id} label={block.title} level={3}>
            {renderInline(block.title, currentSlug, options.resolveHref)}
          </AnchoredHeading>
        </header>
        <div className="docs-function-card-body">
          {block.blocks.map((child, childIndex) =>
            renderBlock(child, childIndex, currentSlug, { ...options, inFunctionCard: true }),
          )}
        </div>
      </section>
    );
  }

  if (block.type === 'heading') {
    const id = slugify(block.text);
    return (
      <AnchoredHeading id={block.depth === 1 ? undefined : id} key={index} level={block.depth as 1 | 2 | 3} label={block.text}>
        {renderInline(block.text, currentSlug, options.resolveHref)}
      </AnchoredHeading>
    );
  }

  if (block.type === 'paragraph') {
    const isFunctionLabel = options.inFunctionCard && /^(Parameters|Returns|Notes):$/.test(block.text);
    return (
      <p className={isFunctionLabel ? 'docs-function-label' : undefined} key={index}>
        {renderInline(block.text, currentSlug, options.resolveHref)}
      </p>
    );
  }

  if (block.type === 'list') {
    const ListTag = block.ordered ? 'ol' : 'ul';
    return (
      <ListTag key={index}>
        {block.items.map((item, itemIndex) => (
          <li key={itemIndex}>{renderInline(item, currentSlug, options.resolveHref)}</li>
        ))}
      </ListTag>
    );
  }

  if (block.type === 'table') {
    return (
      <TableRegion key={index}>
        <table>
          <thead>
            <tr>
              {block.headers.map((header, headerIndex) => (
                <th key={headerIndex}>{renderInline(header, currentSlug, options.resolveHref)}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {block.rows.map((row, rowIndex) => (
              <tr key={rowIndex}>
                {block.headers.map((_, cellIndex) => (
                  <td key={cellIndex}>{renderInline(row[cellIndex] ?? '', currentSlug, options.resolveHref)}</td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </TableRegion>
    );
  }

  return <CodeBlock code={block.code} language={block.language} key={index} />;
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
      blocks.push({ type: 'code', language: fence.at(1) ?? '', code: codeLines.join('\n') });
      continue;
    }

    const heading = trimmed.match(/^(#{1,3})\s+(.+)$/);
    if (heading) {
      blocks.push({ type: 'heading', depth: heading.at(1)?.length ?? 1, text: heading.at(2)?.trim() ?? '' });
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

    if (isTableStart(lines, index)) {
      const headers = splitTableRow(trimmed);
      index += 2;

      const rows: string[][] = [];
      while (index < lines.length && isTableRow(currentLine())) {
        rows.push(splitTableRow(currentLine().trim()));
        index += 1;
      }

      blocks.push({ type: 'table', headers, rows });
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

function groupFunctionDocumentation(blocks: readonly MarkdownBlock[]) {
  const grouped: RenderBlock[] = [];
  let inFunctionDocumentation = false;
  let index = 0;

  while (index < blocks.length) {
    const block = blocks[index];

    if (block.type === 'heading' && block.depth === 2) {
      inFunctionDocumentation = block.text === 'Function Documentation';
      grouped.push(block);
      index += 1;
      continue;
    }

    if (inFunctionDocumentation && block.type === 'heading' && block.depth === 3 && isFunctionHeading(block.text)) {
      const title = block.text;
      const cardBlocks: MarkdownBlock[] = [];
      index += 1;

      while (index < blocks.length) {
        const next = blocks[index];
        if (next.type === 'heading' && (next.depth === 2 || next.depth === 3)) break;
        cardBlocks.push(next);
        index += 1;
      }

      grouped.push({
        type: 'functionCard',
        title,
        id: slugify(title),
        blocks: cardBlocks,
      });
      continue;
    }

    grouped.push(block);
    index += 1;
  }

  return grouped;
}

function isFunctionHeading(text: string) {
  return /^coquic_[A-Za-z0-9_]+\(\)$/.test(text);
}

function isBlockStart(line: string) {
  const trimmed = line.trim();
  return (
    !trimmed ||
    trimmed.startsWith('```') ||
    /^#{1,3}\s+/.test(trimmed) ||
    /^-\s+/.test(trimmed) ||
    /^\d+\.\s+/.test(trimmed)
  );
}

function isIndentedContinuation(line: string) {
  return /^\s{2,}\S/.test(line);
}

function isTableStart(lines: readonly string[], index: number) {
  const header = lines[index]?.trim() ?? '';
  const separator = lines[index + 1]?.trim() ?? '';
  return isTableRow(header) && /^\|?\s*:?-{3,}:?\s*(\|\s*:?-{3,}:?\s*)+\|?$/.test(separator);
}

function isTableRow(line: string) {
  return /^\|.*\|$/.test(line.trim());
}

function splitTableRow(line: string) {
  return line
    .trim()
    .replace(/^\|/, '')
    .replace(/\|$/, '')
    .split('|')
    .map((cell) => cell.trim());
}

function renderInline(
  text: string,
  currentSlug: readonly string[],
  resolveHref: (href: string, currentSlug: readonly string[]) => string,
) {
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
          <Link href={resolveHref(link[2], currentSlug)} key={pieces.length}>
            {renderInline(link[1], currentSlug, resolveHref)}
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

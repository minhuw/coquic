import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { Children, isValidElement, type ReactElement, type ReactNode } from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { BlogPostContent } from '@/components/blog/blog-post-content';
import { CopyCodeButton } from '@/components/docs/copy-code-button';
import { Markdown } from '@/components/docs/markdown';
import { CodeBlock } from '@/components/editorial/code-block';
import { RawCodeBlock } from '@/components/editorial/raw-code-block';
import { TableRegion } from '@/components/editorial/table-region';
import { Prose } from '@/components/typography/prose';
import { hrefForBlogLink, type BlogPost } from '@/lib/blog';
import { hrefForDocLink } from '@/lib/docs';
import { useMDXComponents } from '../mdx-components';

afterEach(cleanup);

function makeBlogPost(markdown: string, format: 'md' | 'mdx' = 'mdx'): BlogPost {
  return {
    slug: 'test-post',
    format,
    title: 'Test post',
    description: 'Test description',
    date: '2026-07-14',
    author: 'CoQUIC',
    polishedBy: '',
    writtenBy: '',
    tags: [],
    readingMinutes: 1,
    markdown,
  };
}

describe('Markdown editorial contracts', () => {
  it('skips only the caller-owned first h1 and preserves heading IDs and function permalinks', async () => {
    const content = await Markdown({
      markdown: `# Caller title

## Function Documentation

### coquic_connect()

Connect to a peer.

## Connection Setup

Ready.`,
      currentSlug: ['api', 'c-ffi-reference'],
      skipFirstH1: true,
    });

    render(content);

    expect(screen.queryAllByRole('heading', { level: 1 })).toHaveLength(0);
    expect(screen.getByRole('heading', { level: 2, name: 'Function Documentation' })).toHaveAttribute(
      'id',
      'function-documentation',
    );
    expect(screen.getByRole('heading', { level: 2, name: 'Connection Setup' })).toHaveAttribute('id', 'connection-setup');
    expect(screen.getByRole('link', { name: 'Permalink to coquic_connect()' })).toHaveAttribute(
      'href',
      '#coquic-connect',
    );
    expect(screen.getByRole('heading', { level: 3, name: 'coquic_connect()' })).toHaveAttribute('id', 'coquic-connect');
  });

  it('keeps internal documentation and blog link resolution contracts', async () => {
    const content = await Markdown({
      markdown: '[API](./c-ffi.md) and [anchor](#connection-setup)',
      currentSlug: ['api', 'quic'],
      resolveHref: hrefForDocLink,
    });
    render(content);

    expect(screen.getByRole('link', { name: 'API' })).toHaveAttribute('href', '/docs/api/c-ffi');
    expect(screen.getByRole('link', { name: 'anchor' })).toHaveAttribute('href', '#connection-setup');

    cleanup();
    const blogContent = await Markdown({
      markdown: '[Why CoQUIC](why-coquic.mdx)',
      currentSlug: ['test-post'],
      resolveHref: hrefForBlogLink,
    });
    render(blogContent);
    expect(screen.getByRole('link', { name: 'Why CoQUIC' })).toHaveAttribute('href', '/blog/why-coquic');
  });

  it('renders lists, semantic tables, known languages, and unknown languages', async () => {
    const markdown = [
      '- first',
      '- not a list item',
      '',
      '1. ordered',
      '2. second',
      '',
      '| Name | Value |',
      '| --- | --- |',
      '| alpha | 1 |',
    ].join('\n');
    const content = await Markdown({
      markdown,
      currentSlug: ['guide'],
    });

    render(content);

    const lists = screen.getAllByRole('list');
    expect(lists).toHaveLength(2);
    expect(lists[0]).toContainElement(screen.getByText('first'));
    expect(lists[0]).toContainElement(screen.getByText('not a list item'));
    expect(lists[1]).toContainElement(screen.getByText('ordered'));
    expect(screen.getByRole('table')).toHaveTextContent('alpha');

    const codeContent = await Markdown({
      markdown: '```zig\nconst value = 1;\n```\n\n```made-up\nopaque contents\n```',
      currentSlug: ['guide'],
    });
    const codeBlocks = Children.toArray((codeContent as ReactElement<{ children?: ReactNode }>).props.children).filter(
      (child): child is ReactElement<{ language: string; code: string }> =>
        isValidElement<{ language: string; code: string }>(child) &&
        typeof child.type === 'function' &&
        child.type.name === 'CodeBlock',
    );
    expect(codeBlocks).toHaveLength(2);
    expect(codeBlocks.map((block) => block.props.language)).toEqual(['zig', 'made-up']);
    expect(codeBlocks.map((block) => block.props.code)).toEqual(['const value = 1;', 'opaque contents']);
  });

  it('groups C API function records without changing their body semantics', async () => {
    const content = await Markdown({
      markdown: `## Function Documentation

### coquic_send()

Parameters:

- data

Returns:

An integer.`,
      currentSlug: ['api', 'c-ffi-reference'],
    });

    render(content);

    const card = document.querySelector('.docs-function-card');
    expect(card).toBeInTheDocument();
    expect(card).toHaveTextContent('Parameters:');
    expect(card).toHaveTextContent('Returns:');
    expect(card).toContainElement(screen.getByRole('list'));
  });
});

describe('MDX editorial contracts', () => {
  it('keeps bilingual panels, authored images, inline code, fenced code, and GFM tables', async () => {
    const mdx = [
      '<BlogLanguagePanel language="en">',
      '',
      '## English section',
      '',
      'Use `coquic_connect`.',
      '',
      '![Packet diagram](/images/packet.png)',
      '',
      '| Field | Value |',
      '| --- | --- |',
      '| state | ready |',
      '',
      '</BlogLanguagePanel>',
      '',
      '<BlogLanguagePanel language="zh">',
      '',
      '## 中文部分',
      '',
      '中文内容。',
      '',
      '</BlogLanguagePanel>',
    ].join('\n');
    const content = await BlogPostContent({
      post: makeBlogPost(mdx),
    });

    render(content);

    expect(screen.getByRole('heading', { level: 2, name: 'English section' })).toBeInTheDocument();
    expect(screen.getByText('coquic_connect')).toBeInTheDocument();
    expect(screen.getByRole('img', { name: 'Packet diagram' })).toHaveAttribute('src', '/images/packet.png');
    expect(screen.getByRole('table')).toHaveTextContent('ready');
    expect(screen.getByText('中文部分')).not.toBeVisible();
    expect(screen.getByText('中文内容。')).not.toBeVisible();

    const pre = useMDXComponents().pre as (props: { children: ReactNode }) => Promise<ReactElement>;
    const codeBlock = await pre({
      children: <code className="language-rust">let ready = true;{`\n`}</code>,
    });
    expect(codeBlock.type).toBe(CodeBlock);
    expect(codeBlock.props).toMatchObject({ code: 'let ready = true;\n', language: 'rust' });
  });
});

describe('copy controls', () => {
  beforeEach(() => {
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: { writeText: vi.fn() },
    });
  });

  it('announces a successful copy', async () => {
    vi.mocked(navigator.clipboard.writeText).mockResolvedValue(undefined);
    render(<CopyCodeButton code="const ready = true;" />);

    fireEvent.click(screen.getByRole('button', { name: 'Copy code' }));

    await waitFor(() => expect(screen.getByRole('button', { name: 'Code copied' })).toBeInTheDocument());
  });

  it('announces clipboard rejection without reporting a false success', async () => {
    vi.mocked(navigator.clipboard.writeText).mockRejectedValueOnce(new Error('permission denied'));
    render(<CopyCodeButton code="const ready = true;" />);

    fireEvent.click(screen.getByRole('button', { name: 'Copy code' }));

    await waitFor(() => expect(screen.getByRole('button', { name: 'Copy failed' })).toBeInTheDocument());
    expect(screen.getByRole('status')).toHaveTextContent('Unable to copy code. Try again.');
  });
});

describe('typed presentation adapters', () => {
  it('keeps prose variants explicit and composes a raw code adapter without Shiki', () => {
    render(
      <Prose variant="compact">
        <p>Compact prose</p>
        <RawCodeBlock code="const raw = true;" language="typescript" variant="compact" />
      </Prose>,
    );

    expect(screen.getByText('Compact prose')).toBeInTheDocument();
    expect(screen.getByText('const raw = true;')).toBeInTheDocument();
    expect(screen.getByText('Compact prose').closest('[data-prose-variant]')).toHaveAttribute('data-prose-variant', 'compact');
  });

  it('retains table semantics while exposing a caption slot', () => {
    render(
      <TableRegion caption="Fixture rows" label="Fixture table" variant="compact">
        <table>
          <thead><tr><th>Key</th></tr></thead>
          <tbody><tr><td>value</td></tr></tbody>
        </table>
      </TableRegion>,
    );

    expect(screen.getByText('Fixture rows')).toBeInTheDocument();
    expect(document.querySelector('[data-editorial-table-region="true"]')).toHaveAttribute('data-table-variant', 'compact');
    expect(screen.getByRole('table')).toHaveTextContent('value');
  });
});

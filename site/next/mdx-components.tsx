import type { MDXComponents } from 'mdx/types';
import { Children, isValidElement, type HTMLAttributes, type ReactNode, type TableHTMLAttributes } from 'react';

import { AnchoredHeading, slugifyHeading, textContent } from '@/components/editorial/anchored-heading';
import { ArticleContent } from '@/components/editorial/article-content';
import { CodeBlock } from '@/components/editorial/code-block';
import { TableRegion } from '@/components/editorial/table-region';

type HeadingProps = HTMLAttributes<HTMLHeadingElement> & {
  children?: ReactNode;
};

type CodeProps = HTMLAttributes<HTMLElement> & {
  children?: ReactNode;
};

function MdxHeading({ children, id, level, ...props }: HeadingProps & { level: 1 | 2 | 3 | 4 | 5 | 6 }) {
  const label = textContent(children).trim();
  return (
    <AnchoredHeading {...props} id={id || slugifyHeading(label) || undefined} label={label} level={level}>
      {children}
    </AnchoredHeading>
  );
}

function MdxTable({ children, ...props }: TableHTMLAttributes<HTMLTableElement>) {
  return (
    <TableRegion>
      <table {...props}>{children}</table>
    </TableRegion>
  );
}

function codeDetails(children: ReactNode) {
  const child = Children.toArray(children).find((item) => isValidElement<CodeProps>(item));
  if (!child || !isValidElement<CodeProps>(child)) {
    return { code: textContent(children), language: '' };
  }

  const className = child.props.className ?? '';
  const language = className.match(/(?:^|\s)language-([^\s]+)/)?.[1] ?? '';
  return { code: textContent(child.props.children), language };
}

async function MdxCodeBlock({ children }: HTMLAttributes<HTMLPreElement>) {
  const { code, language } = codeDetails(children);
  return <CodeBlock code={code} language={language} />;
}

export function useMDXComponents(components: MDXComponents = {}): MDXComponents {
  return {
    wrapper: ArticleContent,
    h1: (props) => <MdxHeading {...props} level={1} />,
    h2: (props) => <MdxHeading {...props} level={2} />,
    h3: (props) => <MdxHeading {...props} level={3} />,
    h4: (props) => <MdxHeading {...props} level={4} />,
    h5: (props) => <MdxHeading {...props} level={5} />,
    h6: (props) => <MdxHeading {...props} level={6} />,
    pre: MdxCodeBlock,
    table: MdxTable,
    ...components,
  };
}

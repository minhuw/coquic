import { Link2 } from 'lucide-react';
import { Children, isValidElement, type HTMLAttributes, type ReactNode } from 'react';

import { cn } from '@/lib/utils';

export type HeadingLevel = 1 | 2 | 3 | 4 | 5 | 6;

type AnchoredHeadingProps = Omit<HTMLAttributes<HTMLHeadingElement>, 'id'> & {
  children: ReactNode;
  id?: string;
  label?: string;
  level: HeadingLevel;
};

const headingTags = {
  1: 'h1',
  2: 'h2',
  3: 'h3',
  4: 'h4',
  5: 'h5',
  6: 'h6',
} as const;

export function AnchoredHeading({ children, className, id, label, level, ...props }: AnchoredHeadingProps) {
  const HeadingTag = headingTags[level];
  const headingLabel = label || textContent(children).trim() || 'heading';

  return (
    <div className="anchored-heading" data-heading-level={level}>
      <HeadingTag {...props} className={cn('anchored-heading__title', className)} id={id}>
        {children}
      </HeadingTag>
      {id ? (
        <a
          aria-label={`Permalink to ${headingLabel}`}
          className="anchored-heading__permalink"
          href={`#${id}`}
          title={`Permalink to ${headingLabel}`}
        >
          <Link2 aria-hidden="true" size={16} strokeWidth={1.8} />
        </a>
      ) : null}
    </div>
  );
}

export function textContent(children: ReactNode): string {
  return Children.toArray(children)
    .map((child) => {
      if (typeof child === 'string' || typeof child === 'number') return String(child);
      if (isValidElement<{ children?: ReactNode }>(child)) return textContent(child.props.children);
      return '';
    })
    .join('');
}

export function slugifyHeading(text: string) {
  return text
    .toLowerCase()
    .replace(/`/g, '')
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '');
}

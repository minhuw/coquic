import { Link2 } from 'lucide-react';
import { Children, isValidElement, type HTMLAttributes, type ReactNode } from 'react';

import { cn } from '@/lib/utils';

import styles from './anchored-heading.module.css';

export type HeadingLevel = 1 | 2 | 3 | 4 | 5 | 6;

type AnchoredHeadingProps = Omit<HTMLAttributes<HTMLHeadingElement>, 'id'> & {
  children: ReactNode;
  headingClassName?: string;
  id?: string;
  label?: string;
  level: HeadingLevel;
  permalinkClassName?: string;
  permalinkLabel?: string;
};

const headingTags = {
  1: 'h1',
  2: 'h2',
  3: 'h3',
  4: 'h4',
  5: 'h5',
  6: 'h6',
} as const;

export function AnchoredHeading({
  children,
  className,
  headingClassName,
  id,
  label,
  level,
  permalinkClassName,
  permalinkLabel,
  ...props
}: AnchoredHeadingProps) {
  const HeadingTag = headingTags[level];
  const headingLabel = label || textContent(children).trim() || 'heading';
  const accessibleLabel = permalinkLabel || `Permalink to ${headingLabel}`;

  return (
    <div className={cn(styles.root, 'anchored-heading', className)} data-heading-level={level}>
      <HeadingTag {...props} className={cn(styles.title, 'anchored-heading__title', headingClassName)} id={id}>
        {children}
      </HeadingTag>
      {id ? (
        <a
          aria-label={accessibleLabel}
          className={cn(styles.permalink, 'anchored-heading__permalink', permalinkClassName)}
          href={`#${id}`}
          title={accessibleLabel}
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

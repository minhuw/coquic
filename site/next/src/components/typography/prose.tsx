import type { ComponentPropsWithoutRef, ReactNode } from 'react';

import { cn } from '@/lib/utils';

import styles from './prose.module.css';

export type ProseVariant = 'compact' | 'editorial' | 'fullWidth';

export type ProseProps = Omit<ComponentPropsWithoutRef<'div'>, 'children'> & {
  children: ReactNode;
  variant?: ProseVariant;
};

/** The only public wrapper for prose content. Keep variants tied to design roles. */
export function Prose({ children, className, variant = 'editorial', ...props }: ProseProps) {
  return (
    <div
      {...props}
      className={cn('prose', styles.root, styles[variant], className)}
      data-prose-variant={variant}
    >
      {children}
    </div>
  );
}

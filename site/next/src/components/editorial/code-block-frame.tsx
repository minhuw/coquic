import type { ReactNode } from 'react';

import { cn } from '@/lib/utils';

import styles from './code-block.module.css';

export type CodeBlockFrameProps = {
  children: ReactNode;
  className?: string;
  language?: string;
  toolbar?: ReactNode;
  variant?: 'compact' | 'default';
};

/** Shared shell for highlighted and raw code adapters. Adapters own parsing. */
export function CodeBlockFrame({
  children,
  className,
  language = '',
  toolbar,
  variant = 'default',
}: CodeBlockFrameProps) {
  const displayLanguage = language || 'text';
  return (
    <div
      className={cn(styles.root, 'editorial-code-block', variant === 'compact' && styles.compact, className)}
      data-editorial-code-block="true"
      data-code-variant={variant}
    >
      <div className={cn(styles.toolbar, 'editorial-code-toolbar')}>
        <span className={cn(styles.language, 'editorial-code-language')}>{displayLanguage}</span>
        {toolbar}
      </div>
      {children}
    </div>
  );
}

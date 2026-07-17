import type { ReactNode } from 'react';

import { ScrollRegion } from '@/components/ui/scroll-region';
import { cn } from '@/lib/utils';

import styles from './table-region.module.css';

export type TableRegionProps = {
  children: ReactNode;
  className?: string;
  label?: string;
  caption?: ReactNode;
  variant?: 'compact' | 'default';
};

export function TableRegion({ caption, children, className, label = 'Data table', variant = 'default' }: TableRegionProps) {
  return (
    <ScrollRegion
      aria-label={label}
      axis="horizontal"
      className={cn(styles.root, variant === 'compact' && styles.compact, 'editorial-table-region', className)}
      data-editorial-table-region="true"
      data-table-variant={variant}
    >
      {caption ? <div className={styles.caption}>{caption}</div> : null}
      {children}
    </ScrollRegion>
  );
}

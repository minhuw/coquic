import type { ReactNode } from 'react';

import { ScrollRegion } from '@/components/ui/scroll-region';
import { cn } from '@/lib/utils';

type TableRegionProps = {
  children: ReactNode;
  className?: string;
  label?: string;
};

export function TableRegion({ children, className, label = 'Data table' }: TableRegionProps) {
  return (
    <ScrollRegion
      aria-label={label}
      axis="horizontal"
      className={cn('editorial-table-region', className)}
      data-editorial-table-region="true"
    >
      {children}
    </ScrollRegion>
  );
}

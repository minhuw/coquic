import * as React from 'react';

import { cn } from '@/lib/utils';

function Skeleton({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      aria-hidden="true"
      className={cn(
        'min-h-[1em] rounded-[var(--radius-control)] bg-[var(--surface-strong)] [animation:foundation-skeleton_1.4s_var(--ease-standard)_infinite_alternate] motion-reduce:[animation-duration:0.001ms] motion-reduce:[animation-iteration-count:1]',
        className,
      )}
      data-skeleton="true"
      {...props}
      data-slot="skeleton"
    />
  );
}

export { Skeleton };

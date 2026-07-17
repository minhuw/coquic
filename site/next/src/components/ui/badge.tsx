import * as React from 'react';
import { cva, type VariantProps } from 'class-variance-authority';

import { cn } from '@/lib/utils';

const badgeVariants = cva(
  'ui-badge inline-flex min-h-[24px] items-center rounded-[var(--radius-control)] border border-[var(--status-neutral-border)] bg-[var(--status-neutral-surface)] px-[var(--space-2)] text-[var(--status-neutral-ink)] tracking-[0] [font:var(--type-metadata)]',
  {
    variants: {
      // Keep historical values as neutral compatibility aliases until route consumers migrate.
      variant: {
        default: '',
        primary: '',
        success: '',
        warning: '',
        danger: '',
      },
    },
    defaultVariants: { variant: 'default' },
  },
);

export interface BadgeProps extends React.HTMLAttributes<HTMLSpanElement>, VariantProps<typeof badgeVariants> {}

function Badge({ className, variant, ...props }: BadgeProps) {
  return (
    <span
      className={cn(badgeVariants({ variant, className }))}
      {...props}
      data-slot="badge"
      data-variant={variant ?? 'default'}
    />
  );
}

export { Badge, badgeVariants };

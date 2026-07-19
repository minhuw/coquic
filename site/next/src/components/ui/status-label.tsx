import * as React from 'react';
import { cva, type VariantProps } from 'class-variance-authority';

import { cn } from '@/lib/utils';

const statusLabelVariants = cva(
  'inline-flex min-h-[24px] items-center rounded-[var(--radius-control)] border px-[var(--space-2)] tracking-[0] [font:var(--type-metadata)]',
  {
    variants: {
      tone: {
        success:
          'border-[var(--status-success-border)] bg-[var(--status-success-surface)] text-[var(--status-success-ink)]',
        warning:
          'border-[var(--status-warning-border)] bg-[var(--status-warning-surface)] text-[var(--status-warning-ink)]',
        danger:
          'border-[var(--status-danger-border)] bg-[var(--status-danger-surface)] text-[var(--status-danger-ink)]',
        neutral:
          'border-[var(--status-neutral-border)] bg-[var(--status-neutral-surface)] text-[var(--status-neutral-ink)]',
        'known-peer':
          'border-[var(--status-known-peer-border)] bg-[var(--status-known-peer-surface)] text-[var(--status-known-peer-ink)]',
      },
    },
    defaultVariants: { tone: 'neutral' },
  },
);

export interface StatusLabelProps
  extends React.HTMLAttributes<HTMLSpanElement>,
    VariantProps<typeof statusLabelVariants> {}

function StatusLabel({ className, tone, ...props }: StatusLabelProps) {
  return (
    <span
      className={cn(statusLabelVariants({ tone, className }))}
      {...props}
      data-slot="status-label"
      data-tone={tone ?? 'neutral'}
    />
  );
}

export { StatusLabel, statusLabelVariants };

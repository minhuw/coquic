import * as React from 'react';
import { cva, type VariantProps } from 'class-variance-authority';

import { cn } from '@/lib/utils';

const badgeVariants = cva(
  'inline-flex min-h-6 items-center rounded-[var(--radius)] border px-2 font-mono text-[11px] font-semibold leading-none',
  {
    variants: {
      variant: {
        default: 'border-[var(--line)] bg-[var(--surface-2)] text-[var(--muted)]',
        primary: 'border-[rgba(15,98,254,0.28)] bg-[var(--primary-soft)] text-[var(--primary)]',
        success: 'border-[rgba(31,138,101,0.28)] bg-[var(--success-soft)] text-[var(--ok)]',
        warning: 'border-[rgba(141,109,0,0.3)] bg-[var(--warning-soft)] text-[var(--warning)]',
        danger: 'border-[rgba(207,45,86,0.28)] bg-[var(--danger-soft)] text-[var(--danger)]',
      },
    },
    defaultVariants: {
      variant: 'default',
    },
  },
);

export interface BadgeProps extends React.HTMLAttributes<HTMLSpanElement>, VariantProps<typeof badgeVariants> {}

function Badge({ className, variant, ...props }: BadgeProps) {
  return <span className={cn(badgeVariants({ variant, className }))} {...props} />;
}

export { Badge, badgeVariants };

import * as React from 'react';
import { cva, type VariantProps } from 'class-variance-authority';

import { cn } from '@/lib/utils';

const statusLabelVariants = cva('status-label', {
  variants: {
    tone: {
      success: 'status-label--success',
      warning: 'status-label--warning',
      danger: 'status-label--danger',
      neutral: 'status-label--neutral',
      'known-peer': 'status-label--known-peer',
    },
  },
  defaultVariants: { tone: 'neutral' },
});

export interface StatusLabelProps
  extends React.HTMLAttributes<HTMLSpanElement>,
    VariantProps<typeof statusLabelVariants> {}

function StatusLabel({ className, tone, ...props }: StatusLabelProps) {
  return <span className={cn(statusLabelVariants({ tone, className }))} {...props} />;
}

export { StatusLabel, statusLabelVariants };

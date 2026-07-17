import * as React from 'react';

import { cn } from '@/lib/utils';

const Card = React.forwardRef<HTMLDivElement, React.HTMLAttributes<HTMLDivElement>>(
  ({ className, ...props }, ref) => (
    <div
      ref={ref}
      className={cn(
        'ui-panel block rounded-[var(--radius-panel)] border border-[var(--border)] bg-[var(--surface)] text-[var(--text)] shadow-none',
        className,
      )}
      {...props}
      data-slot="card"
    />
  ),
);
Card.displayName = 'Card';

const CardHeader = React.forwardRef<HTMLDivElement, React.HTMLAttributes<HTMLDivElement>>(
  ({ className, ...props }, ref) => (
    <div
      ref={ref}
      className={cn(
        'ui-panel__header grid gap-[var(--space-1)] border-b border-[var(--border)] p-[var(--space-4)]',
        className,
      )}
      {...props}
      data-slot="card-header"
    />
  ),
);
CardHeader.displayName = 'CardHeader';

const CardTitle = React.forwardRef<HTMLHeadingElement, React.HTMLAttributes<HTMLHeadingElement>>(
  ({ className, ...props }, ref) => (
    <h2
      ref={ref}
      className={cn('ui-panel__title text-[var(--text-strong)] tracking-[0] [font:var(--type-panel-title)]', className)}
      {...props}
      data-slot="card-title"
    />
  ),
);
CardTitle.displayName = 'CardTitle';

const CardDescription = React.forwardRef<HTMLParagraphElement, React.HTMLAttributes<HTMLParagraphElement>>(
  ({ className, ...props }, ref) => (
    <p
      ref={ref}
      className={cn('ui-panel__description text-[var(--text-muted)] tracking-[0] [font:var(--type-metadata)]', className)}
      {...props}
      data-slot="card-description"
    />
  ),
);
CardDescription.displayName = 'CardDescription';

const CardContent = React.forwardRef<HTMLDivElement, React.HTMLAttributes<HTMLDivElement>>(
  ({ className, ...props }, ref) => (
    <div
      ref={ref}
      className={cn('ui-panel__content p-[var(--space-4)]', className)}
      {...props}
      data-slot="card-content"
    />
  ),
);
CardContent.displayName = 'CardContent';

export { Card, CardContent, CardDescription, CardHeader, CardTitle };

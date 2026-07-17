import * as React from 'react';
import { Slot } from '@radix-ui/react-slot';
import { cva, type VariantProps } from 'class-variance-authority';

import { cn } from '@/lib/utils';

const buttonVariants = cva(
  'ui-button relative inline-flex min-w-0 shrink-0 cursor-pointer items-center justify-center gap-[var(--space-2)] rounded-[var(--radius-control)] border border-transparent px-[var(--space-4)] whitespace-nowrap tracking-[0] no-underline transition-[color,background-color,border-color] duration-[var(--motion-fast)] ease-[var(--ease-standard)] [font:var(--type-ui-label)] focus-visible:outline-2 focus-visible:outline-offset-3 focus-visible:outline-[var(--accent-ink)] focus-visible:shadow-[0_0_0_5px_var(--focus-ring)] aria-busy:cursor-progress disabled:pointer-events-none disabled:cursor-not-allowed disabled:border-[var(--border)] disabled:bg-[var(--surface-strong)] disabled:text-[var(--text-muted)] aria-disabled:pointer-events-none aria-disabled:cursor-not-allowed aria-disabled:border-[var(--border)] aria-disabled:bg-[var(--surface-strong)] aria-disabled:text-[var(--text-muted)] [&_svg]:pointer-events-none [&_svg]:size-[var(--icon-compact)] [&_svg]:shrink-0',
  {
  variants: {
    variant: {
      default:
        'ui-button--default border-[var(--command)] bg-[var(--command)] text-[var(--on-command)] hover:border-[var(--command-hover)] hover:bg-[var(--command-hover)] active:border-[var(--command-active)] active:bg-[var(--command-active)]',
      brand:
        'ui-button--brand border-[var(--accent)] bg-[var(--accent)] text-[var(--on-accent)] hover:border-[var(--accent-hover)] hover:bg-[var(--accent-hover)] active:border-[var(--accent-active)] active:bg-[var(--accent-active)]',
      secondary:
        'ui-button--secondary border-[var(--border)] bg-[var(--surface-subtle)] text-[var(--text-strong)] hover:bg-[var(--surface-strong)] active:bg-[var(--surface-strong)]',
      outline:
        'ui-button--outline border-[var(--control-border)] bg-[var(--surface)] text-[var(--text-strong)] hover:border-[var(--accent-ink)] hover:text-[var(--accent-ink)] active:border-[var(--accent-ink)] active:text-[var(--accent-ink)]',
      ghost:
        'ui-button--ghost border-transparent bg-transparent text-[var(--text-strong)] hover:bg-[var(--surface-subtle)] active:bg-[var(--surface-subtle)]',
      danger:
        'ui-button--danger border-[var(--status-danger-border)] bg-[var(--status-danger-surface)] text-[var(--status-danger-ink)] hover:border-[var(--status-danger-ink)] active:border-[var(--status-danger-ink)]',
      destructive:
        'ui-button--danger border-[var(--status-danger-border)] bg-[var(--status-danger-surface)] text-[var(--status-danger-ink)] hover:border-[var(--status-danger-ink)] active:border-[var(--status-danger-ink)]',
    },
    size: {
      default: 'ui-button--default-size h-[var(--control-default)]',
      sm: 'ui-button--compact h-[var(--control-compact)] px-[var(--space-3)]',
      compact: 'ui-button--compact h-[var(--control-compact)] px-[var(--space-3)]',
      icon: 'ui-button--icon size-[var(--control-default)] p-0',
    },
  },
  defaultVariants: { variant: 'default', size: 'default' },
  },
);

export interface ButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof buttonVariants> {
  asChild?: boolean;
  loading?: boolean;
  loadingLabel?: string;
}

const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  (
    {
      children,
      className,
      variant,
      size,
      asChild = false,
      loading = false,
      loadingLabel = 'Loading',
      disabled,
      ...props
    },
    ref,
  ) => {
    if (asChild) {
      return (
        <Slot
          className={cn(buttonVariants({ variant, size, className }))}
          ref={ref}
          {...props}
          data-size={size ?? 'default'}
          data-slot="button"
          data-variant={variant ?? 'default'}
        >
          {children}
        </Slot>
      );
    }

    return (
      <button
        className={cn(buttonVariants({ variant, size, className }))}
        ref={ref}
        {...props}
        aria-busy={loading || undefined}
        aria-label={loading ? loadingLabel : props['aria-label']}
        data-loading={loading || undefined}
        data-size={size ?? 'default'}
        data-slot="button"
        data-variant={variant ?? 'default'}
        disabled={disabled || loading}
      >
        {loading ? (
          <span
            aria-hidden="true"
            className="ui-button__spinner absolute left-1/2 top-1/2 size-[var(--icon-compact)] -translate-x-1/2 -translate-y-1/2 rounded-full border-2 border-current border-r-transparent motion-safe:animate-spin motion-reduce:animate-none"
            data-slot="button-spinner"
          />
        ) : null}
        <span
          className={cn(
            'ui-button__content inline-flex min-w-0 items-center gap-[var(--space-2)]',
            loading && 'invisible',
          )}
          data-slot="button-content"
        >
          {children}
        </span>
      </button>
    );
  },
);
Button.displayName = 'Button';

export { Button, buttonVariants };

import * as React from 'react';
import { Slot } from '@radix-ui/react-slot';
import { cva, type VariantProps } from 'class-variance-authority';

import { cn } from '@/lib/utils';

const buttonVariants = cva('ui-button', {
  variants: {
    variant: {
      default: 'ui-button--default',
      brand: 'ui-button--brand',
      secondary: 'ui-button--secondary',
      outline: 'ui-button--outline',
      ghost: 'ui-button--ghost',
      danger: 'ui-button--danger',
      destructive: 'ui-button--danger',
    },
    size: {
      default: 'ui-button--default-size',
      sm: 'ui-button--compact',
      compact: 'ui-button--compact',
      icon: 'ui-button--icon',
    },
  },
  defaultVariants: { variant: 'default', size: 'default' },
});

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
        <Slot className={cn(buttonVariants({ variant, size, className }))} ref={ref} {...props}>
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
        disabled={disabled || loading}
      >
        {loading ? <span className="ui-button__spinner" aria-hidden="true" /> : null}
        <span className="ui-button__content">{children}</span>
      </button>
    );
  },
);
Button.displayName = 'Button';

export { Button, buttonVariants };

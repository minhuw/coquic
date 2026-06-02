import * as React from 'react';
import { Slot } from '@radix-ui/react-slot';
import { cva, type VariantProps } from 'class-variance-authority';

import { cn } from '@/lib/utils';

const buttonVariants = cva(
  'inline-flex min-h-10 shrink-0 cursor-pointer items-center justify-center gap-2 rounded-[var(--radius)] border text-sm font-semibold leading-none transition-colors duration-200 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[rgba(15,98,254,0.48)] disabled:pointer-events-none disabled:opacity-55 [&_svg]:pointer-events-none [&_svg]:size-4 [&_svg]:shrink-0',
  {
    variants: {
      variant: {
        default: 'border-[var(--primary)] bg-[var(--primary)] text-white hover:border-[var(--primary-hover)] hover:bg-[var(--primary-hover)]',
        secondary: 'border-[var(--line)] bg-[var(--surface)] text-[var(--ink)] hover:bg-[var(--surface-3)]',
        outline: 'border-[var(--line-strong)] bg-[var(--surface)] text-[var(--ink)] hover:border-[var(--primary)] hover:bg-[#edf5ff] hover:text-[var(--primary)]',
        destructive: 'border-[rgba(207,45,86,0.28)] bg-[#fff1f1] text-[var(--danger)] hover:border-[var(--danger)]',
        ghost: 'border-transparent bg-transparent text-[var(--ink)] hover:bg-[var(--surface-3)]',
      },
      size: {
        default: 'h-10 px-4',
        sm: 'h-9 px-3 text-xs',
        icon: 'size-10 p-0',
      },
    },
    defaultVariants: {
      variant: 'default',
      size: 'default',
    },
  },
);

export interface ButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof buttonVariants> {
  asChild?: boolean;
}

const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant, size, asChild = false, ...props }, ref) => {
    const Comp = asChild ? Slot : 'button';
    return <Comp className={cn(buttonVariants({ variant, size, className }))} ref={ref} {...props} />;
  },
);
Button.displayName = 'Button';

export { Button, buttonVariants };

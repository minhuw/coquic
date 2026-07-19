import type { ReactNode } from 'react';

import { cn } from '@/lib/utils';

type PageHeaderProps = {
  eyebrow?: string;
  title: string;
  description?: ReactNode;
  actions?: ReactNode;
  variant?: 'standard' | 'editorial' | 'tool' | 'evidence' | 'data' | 'operations';
  className?: string;
  containerClassName?: string;
  measureClassName?: string;
};

export function PageHeader({
  eyebrow,
  title,
  description,
  actions,
  variant = 'standard',
  className,
  containerClassName,
  measureClassName,
}: PageHeaderProps) {
  return (
    <header
      className={cn(
        'm-0 border-0 bg-transparent px-0 py-[var(--space-6)] max-md:py-[var(--space-5)] max-md:pb-[var(--space-4)]',
        variant === 'tool' && 'py-[var(--space-5)] pb-[var(--space-4)]',
        className,
      )}
      data-page-header-variant={variant}
      data-slot="page-header"
    >
      <div
        className={cn(
          'grid w-full min-w-0 grid-cols-[minmax(0,1fr)_auto] items-end gap-[var(--space-6)] max-md:grid-cols-[minmax(0,1fr)] max-md:items-start max-md:gap-[var(--space-4)]',
          containerClassName,
        )}
        data-slot="page-header-container"
      >
        <div
          className={cn(
            'grid min-w-0 max-w-[var(--measure-editorial)] gap-[7px] max-md:max-w-full',
            (variant === 'editorial' || variant === 'standard') && 'max-w-[var(--measure-editorial)]',
            (variant === 'evidence' || variant === 'data') && 'max-w-[760px]',
            measureClassName,
          )}
          data-slot="page-header-measure"
        >
          {eyebrow ? (
            <div className="min-w-0" data-slot="page-header-context">
              <span
                className="inline-flex max-w-full items-center gap-[var(--space-2)] text-[var(--accent-ink)] uppercase tracking-[0] [font:var(--type-metadata)] [&::before]:content-none [overflow-wrap:anywhere]"
                data-slot="page-header-eyebrow"
              >
                <span
                  className="size-[7px] shrink-0 bg-[var(--accent-ink)] forced-colors:[background-color:LinkText]"
                  aria-hidden="true"
                  data-slot="page-header-eyebrow-marker"
                />
                {eyebrow}
              </span>
            </div>
          ) : null}
          <h1
            className="m-0 max-w-[var(--measure-editorial)] text-[var(--text-strong)] tracking-[0] [font:var(--type-page-title)] [overflow-wrap:anywhere] max-md:text-[30px] max-md:leading-[1.15]"
            data-slot="page-header-title"
          >
            {title}
          </h1>
          {description ? (
            <div
              className="max-w-[var(--measure-reading)] text-[var(--text-muted)] tracking-[0] [font:var(--type-body)]"
              data-slot="page-header-description"
            >
              {description}
            </div>
          ) : null}
        </div>
        {actions ? (
          <div
            className="flex min-w-0 flex-wrap items-start justify-end gap-[var(--space-2)] pb-[2px] max-md:w-full max-md:justify-start max-md:pb-0"
            data-slot="page-header-actions"
          >
            {actions}
          </div>
        ) : null}
      </div>
    </header>
  );
}

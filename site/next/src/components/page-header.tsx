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
      className={cn('page-header', `page-header--${variant}`, !eyebrow && 'page-header--without-context', className)}
      data-page-header-variant={variant}
    >
      <div className={cn('page-header__container', containerClassName)}>
        <div className={cn('page-header__measure', measureClassName)}>
          {eyebrow ? (
            <div className="page-header__context">
              <span className="eyebrow">
                <span className="page-header__eyebrow-marker" aria-hidden="true" />
                {eyebrow}
              </span>
            </div>
          ) : null}
          <h1 className="page-title">{title}</h1>
          {description ? <div className="page-header__description">{description}</div> : null}
        </div>
        {actions ? <div className="page-header__actions">{actions}</div> : null}
      </div>
    </header>
  );
}

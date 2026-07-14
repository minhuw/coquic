import type { ReactNode } from 'react';

import { cn } from '@/lib/utils';

type PageHeaderProps = {
  eyebrow?: string;
  title: string;
  description?: ReactNode;
  actions?: ReactNode;
  className?: string;
  containerClassName?: string;
  measureClassName?: string;
};

export function PageHeader({
  eyebrow,
  title,
  description,
  actions,
  className,
  containerClassName,
  measureClassName,
}: PageHeaderProps) {
  return (
    <header className={cn('page-header', className)}>
      <div className={cn('page-header__container', containerClassName)}>
        <div className={cn('page-header__measure', measureClassName)}>
          {eyebrow ? <span className="eyebrow">{eyebrow}</span> : null}
          <h1 className="page-title">{title}</h1>
          {description ? <div className="page-header__description">{description}</div> : null}
        </div>
        {actions ? <div className="page-header__actions">{actions}</div> : null}
      </div>
    </header>
  );
}

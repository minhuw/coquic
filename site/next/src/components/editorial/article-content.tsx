import type { ReactNode } from 'react';

import { cn } from '@/lib/utils';

type ArticleContentProps = {
  children: ReactNode;
  className?: string;
};

export function ArticleContent({ children, className }: ArticleContentProps) {
  return <div className={cn('article-content', className)}>{children}</div>;
}

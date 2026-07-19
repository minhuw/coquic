import type { ReactNode } from 'react';

import { Prose, type ProseVariant } from '@/components/typography/prose';

export type ArticleContentProps = {
  children: ReactNode;
  className?: string;
  variant?: ProseVariant;
};

export function ArticleContent({ children, className, variant = 'editorial' }: ArticleContentProps) {
  return <Prose className={className} variant={variant}>{children}</Prose>;
}

import type { ReactNode } from 'react';

import { PageHeader } from '@/components/page-header';
import { Button, type ButtonProps } from '@/components/ui/button';
import { cn } from '@/lib/utils';

import styles from './compliance.module.css';

type CompliancePageProps = {
  eyebrow: string;
  title: string;
  description?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
};

export function CompliancePage({ eyebrow, title, description, actions, children }: CompliancePageProps) {
  return (
    <main className={cn(styles.root, 'mx-auto w-full max-w-[1340px] px-3 pb-10 sm:px-[18px] lg:px-6 lg:pb-14 max-[680px]:px-3 max-[680px]:pb-8')} data-compliance-route="true">
      <PageHeader
        eyebrow={eyebrow}
        title={title}
        description={description}
        actions={actions ? <div className={styles.actions} data-compliance-actions="true">{actions}</div> : undefined}
        variant="evidence"
      />
      {children}
    </main>
  );
}

export function ComplianceAction({ className, ...props }: ButtonProps) {
  return <Button {...props} className={cn(styles.action, className)} />;
}

export { styles as complianceStyles };

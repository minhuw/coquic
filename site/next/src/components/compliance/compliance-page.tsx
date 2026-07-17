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
    <main className={cn('coquic-page', styles.root)} data-compliance-route="true">
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

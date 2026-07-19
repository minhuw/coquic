import type { ReactNode } from 'react';

import { cn } from '@/lib/utils';

import styles from './evidence.module.css';

export type EvidenceTone = 'neutral' | 'success' | 'warning' | 'danger';

export type EvidenceMessageProps = {
  children: ReactNode;
  className?: string;
  hideLabel?: boolean;
  icon?: ReactNode;
  label: string;
  metadata?: string;
  role?: 'assistant' | 'user' | 'neutral';
  tone?: EvidenceTone;
};

export function EvidenceMessage({
  children,
  className = '',
  hideLabel = false,
  icon,
  label,
  metadata,
  role = 'neutral',
  tone = 'neutral',
}: EvidenceMessageProps) {
  return (
    <article
      className={cn(
        styles.message,
        role === 'user' && styles.messageUser,
        className,
      )}
      data-evidence-message="true"
      data-role={role}
      data-tone={tone}
    >
      {icon ? <div className={styles.messageIcon} aria-hidden="true">{icon}</div> : null}
      <div className={styles.messageBody}>
        <header className={styles.messageHeader}>
          <h3 className={cn(styles.messageHeading, hideLabel && styles.visuallyHidden)}>{label}</h3>
          {metadata ? <span className={styles.metadata}>{metadata}</span> : null}
        </header>
        <div className={styles.messageContent}>{children}</div>
      </div>
    </article>
  );
}

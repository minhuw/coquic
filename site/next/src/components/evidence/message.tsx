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
        'evidence-message',
        `evidence-message--${role}`,
        `evidence-message--${tone}`,
        className,
      )}
      data-evidence-message="true"
    >
      {icon ? <div className={cn(styles.messageIcon, 'evidence-message__icon')} aria-hidden="true">{icon}</div> : null}
      <div className={cn(styles.messageBody, 'evidence-message__body')}>
        <header className={cn(styles.messageHeader, 'evidence-message__header')}>
          <h3 className={cn(styles.messageHeading, hideLabel && styles.visuallyHidden, hideLabel && 'evidence-visually-hidden')}>{label}</h3>
          {metadata ? <span className={cn(styles.metadata, 'evidence-message__metadata')}>{metadata}</span> : null}
        </header>
        <div className={cn(styles.messageContent, 'evidence-message__content')}>{children}</div>
      </div>
    </article>
  );
}

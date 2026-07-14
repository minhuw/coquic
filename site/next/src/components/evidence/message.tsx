import type { ReactNode } from 'react';

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
    <article className={`evidence-message evidence-message--${role} evidence-message--${tone} ${className}`.trim()} data-evidence-message="true">
      {icon ? <div className="evidence-message__icon" aria-hidden="true">{icon}</div> : null}
      <div className="evidence-message__body">
        <header className="evidence-message__header">
          <h3 className={hideLabel ? 'evidence-visually-hidden' : undefined}>{label}</h3>
          {metadata ? <span className="evidence-message__metadata">{metadata}</span> : null}
        </header>
        <div className="evidence-message__content">{children}</div>
      </div>
    </article>
  );
}

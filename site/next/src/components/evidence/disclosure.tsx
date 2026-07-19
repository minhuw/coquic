'use client';

import { AlertTriangle, CheckCircle2, ChevronRight, Clock3 } from 'lucide-react';
import { type ReactNode, useId, useState } from 'react';

import { cn } from '@/lib/utils';

import type { EvidenceTone } from './message';
import styles from './evidence.module.css';

export type EvidenceDisclosureProps = {
  children: ReactNode;
  className?: string;
  icon: ReactNode;
  initialOpen?: boolean;
  label: string;
  metadata?: string;
  tone?: EvidenceTone;
};

export function EvidenceDisclosure({
  children,
  className = '',
  icon,
  initialOpen,
  label,
  metadata,
  tone = 'neutral',
}: EvidenceDisclosureProps) {
  const [open, setOpen] = useState(initialOpen ?? (tone === 'danger' || tone === 'warning'));
  const bodyId = useId();
  const titleId = useId();
  const metadataId = useId();
  const outcome = outcomeForTone(tone);

  return (
    <article
      className={cn(
        styles.disclosure,
        tone === 'success' && styles.disclosureSuccess,
        tone === 'warning' && styles.disclosureWarning,
        tone === 'danger' && styles.disclosureDanger,
        open && styles.disclosureOpen,
        className,
      )}
      data-evidence-disclosure="true"
    >
      <button
        aria-controls={bodyId}
        aria-describedby={metadata || outcome ? metadataId : undefined}
        aria-expanded={open}
        aria-labelledby={titleId}
        className={styles.disclosureTrigger}
        onClick={() => setOpen((current) => !current)}
        type="button"
      >
        <span className={styles.disclosureIcon} aria-hidden="true">{icon}</span>
        <span className={styles.disclosureSummary}>
          <span className={styles.disclosureTitle} id={titleId} role="heading" aria-level={3}>{label}</span>
          {metadata || outcome ? (
            <span className={cn(styles.metadata, styles.disclosureMetadata)} id={metadataId}>
              {metadata ? <span>{metadata}</span> : null}
              {outcome ? <span className={cn(styles.outcome, outcome.tone && styles[`outcome${capitalize(outcome.tone)}`])}>{outcome.icon}<span>{outcome.label}</span></span> : null}
            </span>
          ) : null}
        </span>
        <ChevronRight className={styles.chevron} size={16} aria-hidden="true" />
      </button>
      {open ? <div className={styles.body} id={bodyId}>{children}</div> : null}
    </article>
  );
}

function outcomeForTone(tone: EvidenceTone) {
  if (tone === 'success') return { icon: <CheckCircle2 size={14} aria-hidden="true" />, label: 'Complete', tone };
  if (tone === 'warning') return { icon: <Clock3 size={14} aria-hidden="true" />, label: 'Pending', tone };
  if (tone === 'danger') return { icon: <AlertTriangle size={14} aria-hidden="true" />, label: 'Attention', tone };
  return null;
}

function capitalize(value: string) {
  return `${value.slice(0, 1).toUpperCase()}${value.slice(1)}`;
}

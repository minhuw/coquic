'use client';

import { AlertTriangle, CheckCircle2, ChevronRight, Clock3 } from 'lucide-react';
import { type ReactNode, useId, useState } from 'react';

import type { EvidenceTone } from './message';

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
    <article className={`evidence-disclosure evidence-disclosure--${tone} ${open ? 'is-open' : ''} ${className}`.trim()} data-evidence-disclosure="true">
      <button
        aria-controls={bodyId}
        aria-describedby={metadata || outcome ? metadataId : undefined}
        aria-expanded={open}
        aria-labelledby={titleId}
        className="evidence-disclosure__trigger"
        onClick={() => setOpen((current) => !current)}
        type="button"
      >
        <span className="evidence-disclosure__icon" aria-hidden="true">{icon}</span>
        <span className="evidence-disclosure__summary">
          <span className="evidence-disclosure__title" id={titleId} role="heading" aria-level={3}>{label}</span>
          {metadata || outcome ? (
            <span className="evidence-disclosure__metadata" id={metadataId}>
              {metadata ? <span>{metadata}</span> : null}
              {outcome ? <span className="evidence-disclosure__outcome">{outcome.icon}<span>{outcome.label}</span></span> : null}
            </span>
          ) : null}
        </span>
        <ChevronRight className="evidence-disclosure__chevron" size={16} aria-hidden="true" />
      </button>
      {open ? <div className="evidence-disclosure__body" id={bodyId}>{children}</div> : null}
    </article>
  );
}

function outcomeForTone(tone: EvidenceTone) {
  if (tone === 'success') return { icon: <CheckCircle2 size={14} aria-hidden="true" />, label: 'Complete' };
  if (tone === 'warning') return { icon: <Clock3 size={14} aria-hidden="true" />, label: 'Pending' };
  if (tone === 'danger') return { icon: <AlertTriangle size={14} aria-hidden="true" />, label: 'Attention' };
  return null;
}

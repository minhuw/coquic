'use client';

import { Check, CircleAlert, Copy } from 'lucide-react';
import { useEffect, useRef, useState } from 'react';

type CopyCodeButtonProps = {
  code: string;
};

export function CopyCodeButton({ code }: CopyCodeButtonProps) {
  const [status, setStatus] = useState<'idle' | 'copied' | 'error'>('idle');
  const resetTimer = useRef<number | null>(null);

  useEffect(() => {
    return () => {
      if (resetTimer.current !== null) window.clearTimeout(resetTimer.current);
    };
  }, []);

  async function copyCode() {
    if (resetTimer.current !== null) window.clearTimeout(resetTimer.current);

    try {
      await navigator.clipboard.writeText(code);
      setStatus('copied');
      resetTimer.current = window.setTimeout(() => setStatus('idle'), 1600);
    } catch {
      setStatus('error');
    }
  }

  const copied = status === 'copied';
  const failed = status === 'error';
  const label = copied ? 'Code copied' : failed ? 'Copy failed' : 'Copy code';
  const visibleLabel = copied ? 'Copied' : failed ? 'Failed' : 'Copy';
  const announcement = copied ? 'Copied to clipboard.' : failed ? 'Unable to copy code. Try again.' : '';

  return (
    <>
      <button
        aria-label={label}
        className="docs-copy-button editorial-copy-button"
        data-copy-state={status}
        title={label}
        type="button"
        onClick={copyCode}
      >
        {copied ? <Check aria-hidden="true" /> : failed ? <CircleAlert aria-hidden="true" /> : <Copy aria-hidden="true" />}
        <span>{visibleLabel}</span>
      </button>
      <span aria-atomic="true" aria-live="polite" className="editorial-copy-announcement" role="status">
        {announcement}
      </span>
    </>
  );
}

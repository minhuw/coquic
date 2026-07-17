'use client';

import { useCallback, useEffect, useRef, useState, type SyntheticEvent } from 'react';

import { cn } from '@/lib/utils';

import { complianceStyles as styles } from './compliance';

const reportUrl = '/duvet/report.html';
const delayedLoadMs = 15_000;

type DuvetState = 'probing' | 'loading' | 'ready' | 'delayed' | 'unavailable';

function errorReason(error: unknown) {
  return error instanceof Error && error.message ? error.message : 'network request failed';
}

function stateMessage(state: DuvetState, reason: string | null) {
  switch (state) {
    case 'probing':
      return 'Checking whether generated Duvet HTML is available.';
    case 'loading':
      return 'Loading generated Duvet HTML.';
    case 'ready':
      return 'Generated Duvet HTML loaded.';
    case 'delayed':
      return 'Generated Duvet HTML has not loaded after 15 seconds.';
    case 'unavailable':
      return `Generated Duvet HTML is unavailable: ${reason || 'request failed'}.`;
  }
}

export function DuvetReportFrame() {
  const [state, setState] = useState<DuvetState>('probing');
  const [reason, setReason] = useState<string | null>(null);
  const [iframeMounted, setIframeMounted] = useState(false);
  const [attempt, setAttempt] = useState(0);
  const controllerRef = useRef<AbortController | null>(null);
  const timerRef = useRef<number | null>(null);

  const clearDelayTimer = useCallback(() => {
    if (timerRef.current === null) return;
    window.clearTimeout(timerRef.current);
    timerRef.current = null;
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    controllerRef.current = controller;
    let disposed = false;

    setState('probing');
    setReason(null);
    setIframeMounted(false);
    clearDelayTimer();

    void fetch(reportUrl, {
      method: 'HEAD',
      cache: 'no-store',
      signal: controller.signal,
    })
      .then((response) => {
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        if (disposed) return;

        setIframeMounted(true);
        setState('loading');
        timerRef.current = window.setTimeout(() => {
          if (!disposed) setState('delayed');
        }, delayedLoadMs);
      })
      .catch((error: unknown) => {
        if (disposed || (error instanceof DOMException && error.name === 'AbortError')) return;
        clearDelayTimer();
        setState('unavailable');
        setReason(errorReason(error));
      });

    return () => {
      disposed = true;
      controller.abort();
      clearDelayTimer();
    };
  }, [attempt, clearDelayTimer]);

  const retry = useCallback(() => {
    controllerRef.current?.abort();
    clearDelayTimer();
    setIframeMounted(false);
    setReason(null);
    setState('probing');
    setAttempt((current) => current + 1);
  }, [clearDelayTimer]);

  const handleError = useCallback(() => {
    clearDelayTimer();
    setState('unavailable');
    setReason('could not be loaded');
  }, [clearDelayTimer]);

  const handleLoad = useCallback(
    (event: SyntheticEvent<HTMLIFrameElement>) => {
      if (!event.currentTarget.contentDocument?.body?.childElementCount) {
        handleError();
        return;
      }
      clearDelayTimer();
      setReason(null);
      setState('ready');
    },
    [clearDelayTimer, handleError],
  );

  const retryVisible = state === 'delayed' || state === 'unavailable';
  const statusToneClass = {
    probing: undefined,
    loading: undefined,
    ready: styles.duvetStatusReady,
    delayed: styles.duvetStatusDelayed,
    unavailable: styles.duvetStatusUnavailable,
  }[state];

  return (
    <div
      className={styles.duvetReportFrameRegion}
      data-duvet-frame-region="true"
      data-duvet-state={state}
      role="region"
      aria-label="Duvet report viewport"
      tabIndex={0}
    >
      <div className={styles.duvetReportViewport}>
        {iframeMounted ? (
          <iframe
            className={styles.duvetReportFrame}
            src={reportUrl}
            title="Duvet RFC compliance report"
            onLoad={handleLoad}
            onError={handleError}
          />
        ) : (
          <div className={styles.duvetReportPlaceholder} aria-hidden="true" />
        )}
      </div>

      <div
        className={styles.duvetReportState}
        role={state === 'unavailable' ? 'alert' : 'status'}
        aria-live={state === 'unavailable' ? 'assertive' : 'polite'}
      >
        <span className={cn(styles.duvetStatusToken, statusToneClass)}>{state}</span>
        <p data-duvet-reason={state === 'unavailable' || state === 'delayed' ? 'true' : undefined}>
          {stateMessage(state, reason)}
        </p>
        {retryVisible ? (
          <div className={styles.duvetReportStateActions}>
            <button className={styles.inlineAction} type="button" onClick={retry} aria-label="Retry Duvet report">
              Retry
            </button>
            <a className={styles.inlineAction} href={reportUrl}>
              Open HTML
            </a>
          </div>
        ) : null}
      </div>
    </div>
  );
}

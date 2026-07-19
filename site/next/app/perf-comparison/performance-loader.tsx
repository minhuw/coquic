'use client';

import { useEffect } from 'react';

type PerformanceWindow = Window & {
  coquicStartPerformance?: () => void;
};

export function PerformanceLoader() {
  useEffect(() => {
    const performanceWindow = window as PerformanceWindow;
    if (performanceWindow.coquicStartPerformance) {
      performanceWindow.coquicStartPerformance();
      return;
    }

    const existing = document.querySelector<HTMLScriptElement>('script[data-coquic-performance]');
    const script = existing ?? document.createElement('script');
    const start = () => performanceWindow.coquicStartPerformance?.();
    script.addEventListener('load', start, { once: true });
    if (!existing) {
      script.src = '/perf-comparison.js';
      script.type = 'module';
      script.dataset.coquicPerformance = 'true';
      document.body.append(script);
    }
    return () => script.removeEventListener('load', start);
  }, []);

  return null;
}

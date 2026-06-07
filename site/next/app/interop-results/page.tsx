import type { Metadata } from 'next';
import Script from 'next/script';

import { DemoNav } from '@/components/demo-nav';
import { Card } from '@/components/ui/card';

export const metadata: Metadata = {
  title: 'CoQUIC Interop Results',
  other: {
    'coquic-interop-marker': 'coquic-interop-results-v1',
  },
};

export default function InteropPage() {
  return (
    <main className="coquic-page">
      <DemoNav active="interop" />

      <Card className="interop-shell mt-5" aria-label="CoQUIC interop test-case matrix">
        <div className="interop-head">
          <div>
            <h1>CoQUIC Interop Matrix</h1>
            <p id="data-source-label">waiting for interop-results.json</p>
          </div>
          <div className="interop-legend" aria-label="Compatibility result legend">
            <span>
              <i style={{ '--legend-color': 'var(--ok)' } as React.CSSProperties} />
              pass
            </span>
            <span>
              <i style={{ '--legend-color': 'var(--warning)' } as React.CSSProperties} />
              unsupported
            </span>
            <span>
              <i style={{ '--legend-color': 'var(--danger)' } as React.CSSProperties} />
              failed
            </span>
            <span>
              <i style={{ '--legend-color': 'var(--known-broken)' } as React.CSSProperties} />
              known peer-broken
            </span>
            <span>
              <i style={{ '--legend-color': 'var(--muted)' } as React.CSSProperties} />
              not reported
            </span>
          </div>
        </div>
        <div className="compat-wrap">
          <table className="compat-matrix">
            <thead id="matrix-head" />
            <tbody id="matrix-body" />
          </table>
        </div>
      </Card>

      <Script src="/interop-results.js" strategy="afterInteractive" type="module" />
    </main>
  );
}

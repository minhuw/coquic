import type { Metadata } from 'next';

import DemoStaticPage from '../demo-static-page';

export const metadata: Metadata = {
  title: 'CoQUIC Performance Comparison',
  other: {
    'coquic-perf-marker': 'coquic-perf-comparison-v1',
  },
};

export default function PerformancePage() {
  return <DemoStaticPage route="perf-comparison" script="/perf-comparison.js" />;
}

import type { Metadata } from 'next';

import DemoStaticPage from '../demo-static-page';

export const metadata: Metadata = {
  title: 'CoQUIC Coverage Results',
  other: {
    'coquic-coverage-marker': 'coquic-coverage-results-v1',
  },
};

export default function CoveragePage() {
  return <DemoStaticPage route="coverage-results" script="/coverage-results.js" />;
}

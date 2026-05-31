import type { Metadata } from 'next';

import DemoStaticPage from '../demo-static-page';

export const metadata: Metadata = {
  title: 'CoQUIC Interop Results',
  other: {
    'coquic-interop-marker': 'coquic-interop-results-v1',
  },
};

export default function InteropPage() {
  return <DemoStaticPage route="interop-results" script="/interop-results.js" />;
}

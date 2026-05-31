import type { Metadata } from 'next';

import DemoStaticPage from '../demo-static-page';

export const metadata: Metadata = {
  title: 'CoQUIC Protocol Workbench',
  other: {
    'coquic-demo-marker': 'coquic-wasm-demo-v1',
  },
};

export default function WorkbenchPage() {
  return <DemoStaticPage route="workbench" script="/quic-demo.js" moduleScript />;
}

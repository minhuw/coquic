import './globals.css';

import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'CoQUIC demo',
  description: 'CoQUIC HTTP/3, QUIC interop, coverage, and performance dashboard.',
  icons: {
    icon: '/coquic-logo.svg',
  },
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <head>
        <link rel="stylesheet" href="/demo-theme.css" />
      </head>
      <body>{children}</body>
    </html>
  );
}

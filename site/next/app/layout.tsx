import './globals.css';

import type { Metadata } from 'next';

import { ThemeScript } from '@/components/theme-script';

export const metadata: Metadata = {
  title: 'CoQUIC: AI-Generated QUIC, From Prompt to Packet',
  description: 'CoQUIC is an AI-generated QUIC implementation with HTTP/3, protocol QA, interop, coverage, and benchmark dashboards.',
  icons: {
    icon: '/coquic-logo.svg',
  },
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <ThemeScript />
      </head>
      <body>{children}</body>
    </html>
  );
}

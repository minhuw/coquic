import './styles/theme.css';

import type { Metadata } from 'next';

import { DemoNav } from '@/components/demo-nav';
import { ProjectFooter } from '@/components/project-footer';
import shellStyles from '@/components/shell-layout.module.css';
import { ThemeScript } from '@/components/theme-script';
import { googleSansCode, hostGrotesk } from '@/lib/fonts';

export const metadata: Metadata = {
  title: 'CoQUIC: AI-Generated QUIC, From Prompt to Packet',
  description: 'CoQUIC is an AI-generated QUIC implementation with HTTP/3, protocol QA, interop, coverage, and benchmark dashboards.',
  icons: {
    icon: '/coquic-logo.svg',
  },
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en" data-scroll-behavior="smooth" className={`${hostGrotesk.variable} ${googleSansCode.variable}`} suppressHydrationWarning>
      <head>
        <ThemeScript />
      </head>
      <body className={shellStyles.body}>
        <a className={shellStyles.skipLink} href="#shell-main" data-slot="skip-link">
          Skip to content
        </a>
        <DemoNav />
        <div className={shellStyles.main} id="shell-main" data-slot="shell-main" tabIndex={-1}>
          {children}
        </div>
        <ProjectFooter />
        <div id="overlay-root" />
      </body>
    </html>
  );
}

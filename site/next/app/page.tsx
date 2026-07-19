import Link from 'next/link';
import { ArrowUpRight, ShieldCheck } from 'lucide-react';

import { CoquicLogoIcon } from '@/components/icons';
import { HomeArtwork, type HomeArtworkVariant } from '@/components/home-artwork';
import { cn } from '@/lib/utils';

const evidenceItems = [
  { href: '/performance', title: 'Performance', description: 'Throughput and request-rate benchmarks.', art: 'performance' },
  { href: '/interop', title: 'Interop', description: 'Peer and testcase results.', art: 'interop' },
  { href: '/coverage', title: 'Coverage', description: 'Source coverage by path.', art: 'coverage' },
  { href: '/duvet', title: 'Duvet', description: 'RFC requirements mapped to source and tests.', art: 'duvet' },
] as const;

const toolItems = [
  { href: '/workbench', title: 'Workbench', description: 'Packets, streams, and recovery.', art: 'workbench' },
  { href: '/docs/api/integration', title: 'API', description: 'Sans-I/O integration guide.', art: 'api' },
  { href: '/qa', title: 'Ask', description: 'QUIC answers with RFC citations.', art: 'ask' },
  { href: '/transcript', title: 'Dataset', description: 'Public Codex transcripts.', art: 'dataset' },
] as const;

export default function Home() {
  return (
    <main className="max-w-none p-0" data-home-route="home">
      <meta name="coquic-demo-marker" content="coquic-wasm-demo-v1" />
      <meta name="coquic-home-marker" content="coquic-demo-home-v1" />

      <section className="border-b border-[var(--border)] bg-[var(--surface)]" data-home-section="hero" aria-labelledby="home-title">
        <div
          className={cn(
            'container-wide grid min-h-[min(520px,calc(100svh-128px))] grid-cols-[minmax(0,1fr)_minmax(360px,480px)] items-center gap-[var(--space-8)] py-[var(--space-8)]',
            'max-[899px]:grid-cols-[minmax(0,1fr)] max-[899px]:gap-[var(--space-6)]',
            'max-[600px]:min-h-0 max-[600px]:pt-[var(--space-6)] max-[600px]:pb-[var(--space-7)]',
            '[@media(min-width:700px)_and_(max-height:500px)]:min-h-0 [@media(min-width:700px)_and_(max-height:500px)]:grid-cols-[minmax(0,1fr)_minmax(300px,0.8fr)] [@media(min-width:700px)_and_(max-height:500px)]:gap-[var(--space-6)] [@media(min-width:700px)_and_(max-height:500px)]:py-[var(--space-5)]',
          )}
          data-home-slot="hero-inner"
        >
          <div className="w-[min(100%,680px)]" data-home-slot="hero-copy">
            <p className="flex items-center gap-[var(--space-2)] font-mono text-xs leading-[1.45] font-medium text-[var(--text-muted)] uppercase">
              <span
                className="size-2 border border-[var(--accent-ink)] bg-[var(--accent-soft)] forced-colors:border-[CanvasText] forced-colors:bg-[Canvas] forced-colors:text-[CanvasText]"
                aria-hidden="true"
              />
              Experimental / open source
            </p>

            <div
              className={cn(
                'mt-[var(--space-5)] flex items-center gap-[var(--space-4)]',
                'max-[600px]:mt-[var(--space-4)] max-[600px]:gap-[var(--space-3)]',
                '[@media(min-width:700px)_and_(max-height:500px)]:mt-[var(--space-2)] [@media(min-width:700px)_and_(max-height:500px)]:gap-[var(--space-3)]',
              )}
            >
              <CoquicLogoIcon
                className={cn(
                  'size-[72px] shrink-0 basis-[72px] text-[var(--text-strong)]',
                  'max-[600px]:size-12 max-[600px]:basis-12',
                  '[@media(min-width:700px)_and_(max-height:500px)]:size-11 [@media(min-width:700px)_and_(max-height:500px)]:basis-11',
                )}
                aria-hidden="true"
              />
              <h1
                id="home-title"
                className="font-sans text-[64px] leading-none font-medium tracking-[0] text-[var(--text-strong)] max-[600px]:text-[40px] [@media(min-width:700px)_and_(max-height:500px)]:text-[40px]"
              >
                CoQUIC
              </h1>
            </div>

            <p className="mt-[var(--space-3)] font-sans text-2xl leading-[1.25] font-normal text-[var(--text-strong)] max-[600px]:mt-[var(--space-2)] max-[600px]:text-xl [@media(min-width:700px)_and_(max-height:500px)]:mt-[var(--space-1)] [@media(min-width:700px)_and_(max-height:500px)]:text-xl">
              From Prompt to Packet.
            </p>
            <p className="mt-[var(--space-4)] max-w-[600px] font-sans text-base leading-[1.6] font-normal text-[var(--text-muted)] max-[600px]:mt-[var(--space-3)] [@media(min-width:700px)_and_(max-height:500px)]:mt-[var(--space-2)]">
              Experimental QUIC and HTTP/3, generated with Codex.
            </p>
          </div>

          <Link
            className={cn(
              'grid min-h-[240px] min-w-0 content-center border-l border-[var(--border)] py-[var(--space-7)] pr-0 pl-[var(--space-7)] text-[var(--text)] no-underline [transition:background-color_var(--motion-fast)_var(--ease-standard)] hover:bg-[var(--surface-subtle)] motion-reduce:transition-none',
              'max-[899px]:min-h-0 max-[899px]:w-[min(100%,680px)] max-[899px]:border-t max-[899px]:border-l-0 max-[899px]:pt-[var(--space-6)] max-[899px]:pr-0 max-[899px]:pb-0 max-[899px]:pl-0',
              'max-[600px]:pt-[var(--space-5)]',
              '[@media(min-width:700px)_and_(max-height:500px)]:w-auto [@media(min-width:700px)_and_(max-height:500px)]:border-t-0 [@media(min-width:700px)_and_(max-height:500px)]:border-l [@media(min-width:700px)_and_(max-height:500px)]:py-[var(--space-3)] [@media(min-width:700px)_and_(max-height:500px)]:pr-0 [@media(min-width:700px)_and_(max-height:500px)]:pl-[var(--space-6)]',
            )}
            data-home-destination="steward"
            href="/steward"
            aria-label="Open Steward"
          >
            <span className="inline-flex items-center gap-[var(--space-2)] font-sans text-sm leading-[1.4] font-medium text-[var(--accent-ink)]">
              <ShieldCheck aria-hidden="true" size={20} />
              Steward
            </span>
            <strong className="mt-[var(--space-5)] max-w-[360px] font-sans text-[28px] leading-[1.3] font-medium text-[var(--text-strong)] max-[600px]:mt-[var(--space-3)] max-[600px]:text-[22px] [@media(min-width:700px)_and_(max-height:500px)]:mt-[var(--space-3)] [@media(min-width:700px)_and_(max-height:500px)]:text-[22px]">
              Repository tasks and automation
            </strong>
            <span
              className={cn(
                'mt-[var(--space-7)] flex min-w-0 items-center justify-between gap-[var(--space-4)] border-t border-[var(--border)] pt-[var(--space-4)] font-sans text-sm leading-[1.4] font-medium text-[var(--accent-ink)]',
                'max-[899px]:mt-[var(--space-5)]',
                'max-[600px]:mt-[var(--space-4)] max-[600px]:min-h-[var(--control-coarse)] max-[600px]:pt-[var(--space-3)]',
                '[@media(min-width:700px)_and_(max-height:500px)]:mt-[var(--space-3)] [@media(min-width:700px)_and_(max-height:500px)]:pt-[var(--space-2)]',
              )}
            >
              Open Steward
              <ArrowUpRight aria-hidden="true" size={18} />
            </span>
          </Link>
        </div>
      </section>

      <HomeIndex
        tone="evidence"
        heading="Evidence"
        items={evidenceItems}
        label="Engineering evidence"
      />

      <HomeIndex
        tone="tools"
        heading="Tools"
        items={toolItems}
        label="Project tools"
      />
    </main>
  );
}

function HomeIndex({
  tone,
  heading,
  items,
  label,
}: {
  tone: 'evidence' | 'tools';
  heading: string;
  items: ReadonlyArray<{
    href: string;
    title: string;
    description: string;
    art: HomeArtworkVariant;
  }>;
  label: string;
}) {
  const headingId = `home-${heading.toLowerCase()}-title`;

  return (
    <section
      className={cn(
        'border-b border-[var(--border)]',
        tone === 'evidence'
          ? 'bg-[var(--surface-subtle)] [--art-surface:var(--surface)] [--art-paper:var(--canvas)]'
          : 'bg-[var(--surface)] [--art-surface:var(--surface-subtle)] [--art-paper:var(--surface)]',
      )}
      data-home-section={tone}
      aria-labelledby={headingId}
    >
      <div
        className={cn(
          'container-wide grid grid-cols-[minmax(160px,220px)_minmax(0,1fr)] items-stretch py-[var(--space-8)]',
          'max-[1100px]:grid-cols-[minmax(140px,160px)_minmax(0,1fr)]',
          'max-[1023px]:grid-cols-[minmax(0,1fr)] max-[1023px]:gap-[var(--space-5)] max-[1023px]:py-[var(--space-7)]',
        )}
        data-home-slot="index-inner"
      >
        <h2
          id={headingId}
          className="flex items-center border-y border-[var(--border-strong)] pr-[var(--space-6)] font-sans text-2xl leading-[1.3] font-medium text-[var(--text-strong)] max-[1100px]:pr-[var(--space-4)] max-[1023px]:border-0 max-[1023px]:pr-0"
        >
          {heading}
        </h2>
        <nav
          className="grid grid-cols-4 border-y border-[var(--border-strong)] max-[1023px]:grid-cols-2 max-[600px]:grid-cols-1"
          data-home-slot="index-links"
          aria-label={label}
        >
          {items.map((item, index) => {
            return (
              <Link
                className={cn(
                  'flex min-h-[260px] min-w-0 flex-col items-start gap-[var(--space-5)] p-[var(--space-5)] text-[var(--text)] no-underline [transition:background-color_var(--motion-fast)_var(--ease-standard)] motion-reduce:transition-none',
                  tone === 'evidence' ? 'hover:bg-[var(--canvas)]' : 'hover:bg-[var(--surface-subtle)]',
                  index > 0 && 'border-l border-[var(--border)]',
                  index >= 2 && 'max-[1023px]:border-t max-[600px]:border-t-0',
                  index === 2 && 'max-[1023px]:border-l-0',
                  index === 1 && 'max-[600px]:border-t',
                  'max-[1100px]:min-h-[220px] max-[1100px]:gap-[var(--space-3)] max-[1100px]:p-[var(--space-3)]',
                  'max-[1023px]:grid max-[1023px]:min-h-[160px] max-[1023px]:grid-cols-[96px_minmax(0,1fr)] max-[1023px]:items-center max-[1023px]:gap-[var(--space-4)] max-[1023px]:p-[var(--space-4)]',
                  'max-[600px]:min-h-[112px] max-[600px]:grid-cols-[80px_minmax(0,1fr)] max-[600px]:gap-[var(--space-3)] max-[600px]:px-0',
                )}
                data-home-destination={item.title.toLowerCase()}
                href={item.href}
                key={item.href}
              >
                <HomeArtwork variant={item.art} />
                <span className="grid w-full flex-1 grid-cols-[minmax(0,1fr)_auto] items-start gap-[var(--space-3)] max-[1100px]:gap-[var(--space-2)]">
                  <span className="grid min-w-0 gap-[var(--space-1)]">
                    <strong className="min-w-0 font-sans text-base leading-[1.4] font-semibold text-[var(--text-strong)] [overflow-wrap:anywhere]">
                      {item.title}
                    </strong>
                    <span className="font-sans text-sm leading-[1.5] font-normal text-[var(--text-muted)] [overflow-wrap:anywhere]">
                      {item.description}
                    </span>
                  </span>
                  <ArrowUpRight className="mt-0.5 text-[var(--accent-ink)]" aria-hidden="true" size={16} />
                </span>
              </Link>
            );
          })}
        </nav>
      </div>
    </section>
  );
}

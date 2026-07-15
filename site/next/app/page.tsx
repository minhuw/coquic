import Link from 'next/link';
import { ArrowUpRight, ShieldCheck } from 'lucide-react';

import { CoquicLogoIcon } from '@/components/icons';
import { HomeArtwork, type HomeArtworkVariant } from '@/components/home-artwork';

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
    <main className="coquic-page home-page">
      <meta name="coquic-demo-marker" content="coquic-wasm-demo-v1" />
      <meta name="coquic-home-marker" content="coquic-demo-home-v1" />

      <section className="home-hero" aria-labelledby="home-title">
        <div className="home-hero-inner container-wide">
          <div className="home-hero-copy">
            <p className="home-kicker">
              <span className="home-kicker-marker" aria-hidden="true" />
              Experimental / open source
            </p>

            <div className="home-brand-lockup">
              <CoquicLogoIcon className="home-mark" aria-hidden="true" />
              <h1 id="home-title" className="home-title">CoQUIC</h1>
            </div>

            <p className="home-slogan">From Prompt to Packet.</p>
            <p className="home-description">
              Experimental QUIC and HTTP/3, generated with Codex.
            </p>
          </div>

          <Link className="home-steward-feature" href="/steward" aria-label="Open Steward">
            <span className="home-steward-label">
              <ShieldCheck aria-hidden="true" size={20} />
              Steward
            </span>
            <strong>Repository tasks and automation</strong>
            <span className="home-steward-action">
              Open Steward
              <ArrowUpRight aria-hidden="true" size={18} />
            </span>
          </Link>
        </div>
      </section>

      <HomeIndex
        className="home-evidence"
        heading="Evidence"
        items={evidenceItems}
        label="Engineering evidence"
      />

      <HomeIndex
        className="home-tools"
        heading="Tools"
        items={toolItems}
        label="Project tools"
      />
    </main>
  );
}

function HomeIndex({
  className,
  heading,
  items,
  label,
}: {
  className: string;
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
    <section className={`home-index ${className}`} aria-labelledby={headingId}>
      <div className="home-index-inner container-wide">
        <h2 id={headingId}>{heading}</h2>
        <nav className="home-index-links" aria-label={label}>
          {items.map((item) => {
            return (
              <Link href={item.href} key={item.href}>
                <HomeArtwork variant={item.art} />
                <span className="home-index-card-body">
                  <span className="home-index-copy">
                    <strong>{item.title}</strong>
                    <span>{item.description}</span>
                  </span>
                  <ArrowUpRight aria-hidden="true" size={16} />
                </span>
              </Link>
            );
          })}
        </nav>
      </div>
    </section>
  );
}

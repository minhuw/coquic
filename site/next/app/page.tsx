import Link from 'next/link';
import { ArrowUpRight, ShieldCheck } from 'lucide-react';

import { CoquicLogoIcon } from '@/components/icons';
import { HomeArtwork, type HomeArtworkVariant } from '@/components/home-artwork';

import styles from './home.module.css';

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
    <main className={`coquic-page ${styles.page}`} data-home-route="home">
      <meta name="coquic-demo-marker" content="coquic-wasm-demo-v1" />
      <meta name="coquic-home-marker" content="coquic-demo-home-v1" />

      <section className={styles.hero} data-home-section="hero" aria-labelledby="home-title">
        <div className={`${styles['hero-inner']} container-wide`} data-home-slot="hero-inner">
          <div className={styles['hero-copy']} data-home-slot="hero-copy">
            <p className={styles.kicker}>
              <span className={styles['kicker-marker']} aria-hidden="true" />
              Experimental / open source
            </p>

            <div className={styles['brand-lockup']}>
              <CoquicLogoIcon className={styles.mark} aria-hidden="true" />
              <h1 id="home-title" className={styles.title}>CoQUIC</h1>
            </div>

            <p className={styles.slogan}>From Prompt to Packet.</p>
            <p className={styles.description}>
              Experimental QUIC and HTTP/3, generated with Codex.
            </p>
          </div>

          <Link className={styles.steward} data-home-destination="steward" href="/steward" aria-label="Open Steward">
            <span className={styles['steward-label']}>
              <ShieldCheck aria-hidden="true" size={20} />
              Steward
            </span>
            <strong>Repository tasks and automation</strong>
            <span className={styles['steward-action']}>
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
  const sectionClassName = tone === 'evidence' ? styles.evidence : styles.tools;

  return (
    <section className={`${styles.index} ${sectionClassName}`} data-home-section={tone} aria-labelledby={headingId}>
      <div className={`${styles['index-inner']} container-wide`} data-home-slot="index-inner">
        <h2 id={headingId}>{heading}</h2>
        <nav className={styles['index-links']} data-home-slot="index-links" aria-label={label}>
          {items.map((item) => {
            return (
              <Link data-home-destination={item.title.toLowerCase()} href={item.href} key={item.href}>
                <HomeArtwork variant={item.art} />
                <span className={styles['card-body']}>
                  <span className={styles.copy}>
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

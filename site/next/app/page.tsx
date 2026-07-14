import Link from 'next/link';
import { ArrowUpRight, BookOpen, ChevronRight } from 'lucide-react';

import { CoquicLogoIcon } from '@/components/icons';

const taskItems = [
  {
    href: '/workbench',
    title: 'Inspect protocol behavior',
    description: 'Run the default transfer scenario and inspect packets, endpoints, streams, and recovery state.',
  },
  {
    href: '/docs/api/integration',
    title: 'Integrate the API',
    description: 'Follow the runtime event loop and public wrapper guidance for a sans-I/O integration.',
  },
  {
    href: '/duvet',
    title: 'Review evidence',
    description: 'Trace RFC requirements to implementation citations and tests in the Duvet report.',
  },
  {
    href: '/blog',
    title: 'Browse development history',
    description: 'Read project notes, implementation updates, interop findings, and benchmark observations.',
  },
  {
    href: '/steward',
    title: 'Monitor Steward',
    description: 'Inspect public repository stewardship tasks and planner history.',
  },
] as const;

export default function Home() {
  return (
    <main className="coquic-page home-page">
      <meta name="coquic-demo-marker" content="coquic-wasm-demo-v1" />
      <meta name="coquic-home-marker" content="coquic-demo-home-v1" />

      <div className="home-container container-focused">
        <section className="home-portal" aria-labelledby="home-title">
          <div className="home-intro">
            <CoquicLogoIcon className="home-mark" aria-hidden="true" />
            <h1 id="home-title" className="home-title">
              CoQUIC
            </h1>
            <p className="home-slogan">From Prompt to Packet.</p>
            <p className="home-description">
              CoQUIC is an open-source QUIC implementation, made inspectable through protocol state and engineering evidence.
            </p>

            <div className="home-actions" aria-label="Project entry points">
              <Link className="ui-button ui-button--default ui-button--default-size home-action-primary" href="/workbench">
                <span className="ui-button__content">
                  <span>Open Workbench</span>
                  <ArrowUpRight aria-hidden="true" size={16} />
                </span>
              </Link>
              <Link className="home-action-secondary" href="/docs">
                <BookOpen aria-hidden="true" size={16} />
                <span>Read the docs</span>
              </Link>
              <Link className="home-action-resource" href="/interop">
                <span>View interop evidence</span>
                <ArrowUpRight aria-hidden="true" size={16} />
              </Link>
            </div>
          </div>

          <section className="home-preview" aria-labelledby="preview-title">
            <div className="home-preview-header">
              <div>
                <p className="home-eyebrow">scenario preview</p>
                <h2 id="preview-title">Transfer scenario preview</h2>
              </div>
              <Link className="home-preview-link" href="/workbench">
                <span>Open scenario in Workbench</span>
                <ArrowUpRight aria-hidden="true" size={16} />
              </Link>
            </div>
            <p className="home-preview-description">
              Scenario preview only. The default Transfer scenario represents client and server paths across the Initial, Handshake, and 1-RTT packet spaces.
            </p>

            <div className="home-protocol-visual" aria-label="Client and server protocol channels">
              <div className="home-endpoint home-endpoint-client">
                <span className="home-endpoint-token" aria-hidden="true">C</span>
                <strong>Client</strong>
                <span>browser endpoint</span>
              </div>

              <div className="home-protocol-flow">
                <div className="home-lane home-lane-client">
                  <span className="home-direction">client to server</span>
                  <span className="home-wire" aria-hidden="true">
                    <span className="home-packet home-packet-client home-packet-one" />
                    <span className="home-packet home-packet-client home-packet-two" />
                    <span className="home-packet home-packet-client home-packet-three" />
                  </span>
                </div>
                <div className="home-lane home-lane-server">
                  <span className="home-direction">server to client</span>
                  <span className="home-wire" aria-hidden="true">
                    <span className="home-packet home-packet-server home-packet-one" />
                    <span className="home-packet home-packet-server home-packet-two" />
                    <span className="home-packet home-packet-server home-packet-three" />
                  </span>
                </div>
                <ol className="home-stage-track" aria-label="QUIC packet stages">
                  <li><span className="home-stage-marker" aria-hidden="true" />Initial</li>
                  <li><span className="home-stage-marker" aria-hidden="true" />Handshake</li>
                  <li><span className="home-stage-marker" aria-hidden="true" />1-RTT</li>
                </ol>
              </div>

              <div className="home-endpoint home-endpoint-server">
                <span className="home-endpoint-token" aria-hidden="true">S</span>
                <strong>Server</strong>
                <span>browser endpoint</span>
              </div>
            </div>
          </section>
        </section>

        <section className="home-tasks" aria-labelledby="task-index-title">
          <div className="home-section-heading">
            <div>
              <p className="home-eyebrow">project index</p>
              <h2 id="task-index-title">Pick a project job</h2>
            </div>
            <p>Use the real site surfaces to inspect, integrate, review, and follow the project.</p>
          </div>

          <div className="home-task-list">
            {taskItems.map((item) => (
              <Link className="home-task-row" href={item.href} key={item.href}>
                <span className="home-task-copy">
                  <strong>{item.title}</strong>
                  <span>{item.description}</span>
                </span>
                <ChevronRight aria-hidden="true" size={18} />
              </Link>
            ))}
          </div>
        </section>
      </div>
    </main>
  );
}

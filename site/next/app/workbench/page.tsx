import type { Metadata } from 'next';
import Script from 'next/script';
import { Play, Shuffle, Square, StepForward, X } from 'lucide-react';

import { DemoNav } from '@/components/demo-nav';
import { PageHeader } from '@/components/page-header';

export const metadata: Metadata = {
  title: 'CoQUIC Protocol Workbench',
  other: {
    'coquic-demo-marker': 'coquic-wasm-demo-v1',
  },
};

type Endpoint = {
  key: 'client' | 'server';
  label: string;
  role: string;
};

const endpoints: Endpoint[] = [
  { key: 'client', label: 'Client Endpoint', role: 'active opener' },
  { key: 'server', label: 'Server Endpoint', role: 'TLS terminator' },
];

const miniStats = ['state', 'connection', 'wakeup', 'version', 'sent', 'received', 'events', 'stream-count'] as const;

function statLabel(key: (typeof miniStats)[number]) {
  const labels: Record<(typeof miniStats)[number], string> = {
    state: 'State',
    connection: 'Connection',
    wakeup: 'Wakeup',
    version: 'Version',
    sent: 'Sent',
    received: 'Received',
    events: 'Events',
    'stream-count': 'Streams',
  };
  return labels[key];
}

function initialStatValue(key: (typeof miniStats)[number]) {
  if (key === 'sent' || key === 'received') return '0 / 0B';
  if (key === 'events') return '0';
  if (key === 'stream-count') return '0 active';
  if (key === 'connection' || key === 'wakeup' || key === 'version') return 'none';
  return 'idle';
}

function EndpointPanel({ endpoint }: { endpoint: Endpoint }) {
  const prefix = endpoint.key;

  return (
    <div className={`endpoint ${prefix}`}>
      <div className="endpoint-head">
        <div className="role">{prefix === 'client' ? 'C' : 'S'}</div>
        <div className="endpoint-title">
          <h2>{endpoint.label}</h2>
          <span>{endpoint.role}</span>
        </div>
        <div id={`${prefix}-endpoint-chip`} className="endpoint-chip">
          no connection
        </div>
      </div>

      <div id={`${prefix}-state-machine`} className="state-machine" />

      <dl className="mini-stats">
        {miniStats.map((stat) => (
          <div className="diag-stat" key={stat}>
            <dt>{statLabel(stat)}</dt>
            <dd id={`${prefix}-${stat}`}>{initialStatValue(stat)}</dd>
          </div>
        ))}
      </dl>

      <div className="diag-section">
        <div className="diag-section-head">
          <h3>Path And Recovery</h3>
          <span id={`${prefix}-recovery-caption`} className="diag-caption">
            newreno
          </span>
        </div>
        <dl id={`${prefix}-path-flags`} className="flag-grid" />
        <dl id={`${prefix}-recovery`} className="recovery-grid" />
      </div>

      <div className="diag-section">
        <div className="diag-section-head">
          <h3>Packet Spaces</h3>
          <span id={`${prefix}-packet-caption`} className="diag-caption">
            Initial / Handshake / 1-RTT
          </span>
        </div>
        <div id={`${prefix}-packet-spaces`} className="diag-table-wrap" />
      </div>

      <div className="diag-section">
        <div className="diag-section-head">
          <h3>Flow Control</h3>
          <span className="diag-caption">connection window</span>
        </div>
        <dl id={`${prefix}-flow`} className="flow-grid" />
        <dl id={`${prefix}-stream-limits`} className="stream-limit-grid" />
      </div>

      <div className="diag-section">
        <div className="diag-section-head">
          <h3>Streams</h3>
          <span id={`${prefix}-stream-caption`} className="diag-caption">
            none
          </span>
        </div>
        <div id={`${prefix}-streams`} className="diag-table-wrap" />
      </div>
    </div>
  );
}

export default function WorkbenchPage() {
  return (
    <>
      <main className="coquic-page">
        <DemoNav active="workbench" />
        <PageHeader eyebrow="wasm QUIC laboratory" title="CoQUIC Protocol Workbench" />

        <section className="packet-stage" aria-label="QUIC packet exchange">
          <div className="stage-node stage-client">
            <span>C</span>
            <strong>Client</strong>
            <small>browser endpoint</small>
          </div>

          <div id="packet-rail" className="packet-rail">
            <div className="packet-lane c2s">
              <span className="pipe-back" aria-hidden="true" />
              <span className="pipe-front" aria-hidden="true" />
              <span className="lane-end lane-left">C</span>
              <span className="lane-end lane-right">S</span>
            </div>
            <div className="packet-lane s2c">
              <span className="pipe-back" aria-hidden="true" />
              <span className="pipe-front" aria-hidden="true" />
              <span className="lane-end lane-left">C</span>
              <span className="lane-end lane-right">S</span>
            </div>
          </div>

          <div className="stage-node stage-server">
            <span>S</span>
            <strong>Server</strong>
            <small>browser endpoint</small>
          </div>

          <div className="stage-controls" aria-label="Debugger controls">
            <div className="control-timer" aria-live="polite">
              <span>Global Timer</span>
              <strong id="global-timer">0ms</strong>
            </div>
            <div id="module-state" className="module-state" aria-live="polite">
              loading wasm
            </div>
            <div className="loss-control" aria-label="Packet loss simulation">
              <button
                id="loss-toggle"
                className="loss-toggle"
                type="button"
                aria-pressed="false"
                aria-label="Toggle packet loss simulation"
              >
                <span className="control-icon" aria-hidden="true">
                  <Shuffle />
                </span>
                <span className="control-label">Loss</span>
              </button>
              <label className="loss-rate" htmlFor="loss-rate">
                <span id="loss-rate-label">0%</span>
                <input id="loss-rate" type="range" min="0" max="40" step="5" defaultValue="15" />
              </label>
            </div>
            <button id="start" className="control-button" type="button" aria-label="Start protocol exchange">
              <span className="control-icon" aria-hidden="true">
                <Play />
              </span>
              <span id="start-label" className="control-label">
                Start
              </span>
            </button>
            <button id="stop" className="control-button" type="button" aria-label="Stop protocol exchange">
              <span className="control-icon" aria-hidden="true">
                <Square />
              </span>
              <span className="control-label">Stop</span>
            </button>
            <button id="step" className="control-button" type="button" aria-label="Step one protocol action">
              <span className="control-icon" aria-hidden="true">
                <StepForward />
              </span>
              <span id="step-label" className="control-label">
                Step
              </span>
            </button>
          </div>
        </section>

        <section className="workbench" aria-label="Endpoint diagnostics">
          <div className="endpoint-grid">
            {endpoints.map((endpoint) => (
              <EndpointPanel endpoint={endpoint} key={endpoint.key} />
            ))}
          </div>

          <div className="timeline">
            <h2>Datagram And Event Trace</h2>
            <div id="log" className="log" />
          </div>
        </section>

        <section className="packet-inspector" aria-label="Packet capture inspector">
          <div className="capture-panel">
            <div className="panel-head">
              <h2>Packet Log</h2>
              <div className="panel-actions">
                <button id="download-pcap" className="panel-button" type="button" disabled>
                  Download PCAP
                </button>
                <span id="packet-count">0 captured</span>
              </div>
            </div>
            <div id="packet-list" className="packet-list" />
          </div>

          <span id="packet-selected" hidden>
            none selected
          </span>
          <div id="packet-detail" hidden />
        </section>

        <Script src="/quic-demo.js" strategy="afterInteractive" type="module" />
      </main>

      <div id="packet-modal" className="modal-backdrop" aria-hidden="true">
        <section className="packet-modal" role="dialog" aria-modal="true" aria-labelledby="packet-modal-title">
          <div className="modal-head">
            <div>
              <h2 id="packet-modal-title">Packet Details</h2>
              <span id="packet-modal-selected">none selected</span>
            </div>
            <button id="packet-modal-close" className="modal-close" type="button" aria-label="Close packet details">
              <X aria-hidden="true" className="size-4" />
            </button>
          </div>
          <div id="packet-modal-detail" className="packet-detail modal-detail">
            <p className="empty-detail">Select a packet to inspect its QUIC header, protected payload, and raw bytes.</p>
          </div>
        </section>
      </div>
    </>
  );
}

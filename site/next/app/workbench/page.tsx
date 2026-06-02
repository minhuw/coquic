import type { Metadata } from 'next';
import Script from 'next/script';
import { Gauge, ListChecks, Play, Square, StepForward, X } from 'lucide-react';

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

const interopPresets = [
  ['handshake', 'Handshake'],
  ['handshakeloss', 'Handshake Loss'],
  ['transfer', 'Transfer'],
  ['keyupdate', 'Key Update'],
  ['transferloss', 'Transfer Loss'],
  ['handshakecorruption', 'Handshake Corruption'],
  ['transfercorruption', 'Transfer Corruption'],
  ['blackhole', 'Blackhole'],
  ['chacha20', 'ChaCha20'],
  ['longrtt', 'Long RTT'],
  ['ipv6', 'IPv6'],
  ['multiplexing', 'Multiplexing'],
  ['retry', 'Retry'],
  ['resumption', 'Resumption'],
  ['zerortt', '0-RTT'],
  ['v2', 'Version 2'],
  ['amplificationlimit', 'Amplification Limit'],
  ['rebind-port', 'Rebind Port'],
  ['rebind-addr', 'Rebind Addr'],
  ['connectionmigration', 'Connection Migration'],
  ['ecn', 'ECN'],
  ['goodput', 'Goodput'],
  ['crosstraffic', 'Cross Traffic'],
] as const;

function statLabel(key: (typeof miniStats)[number]) {
  switch (key) {
    case 'state':
      return 'State';
    case 'connection':
      return 'Connection';
    case 'wakeup':
      return 'Wakeup';
    case 'version':
      return 'Version';
    case 'sent':
      return 'Sent';
    case 'received':
      return 'Received';
    case 'events':
      return 'Events';
    case 'stream-count':
      return 'Streams';
  }
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

        <div className="scenario-toolbar" aria-label="Interop case controls">
          <label className="scenario-control" htmlFor="scenario-preset">
            <span className="scenario-label">
              <span className="control-icon" aria-hidden="true">
                <ListChecks />
              </span>
              <span>Interop Case</span>
            </span>
            <select id="scenario-preset" className="scenario-select" defaultValue="transfer">
              {interopPresets.map(([value, label]) => (
                <option value={value} key={value}>
                  {label}
                </option>
              ))}
            </select>
            <span id="scenario-summary" className="scenario-summary">
              Stream transfer with packet inspection.
            </span>
          </label>
          <div className="network-control" aria-label="Network environment">
            <span className="network-control-head">
              <span className="control-icon" aria-hidden="true">
                <Gauge />
              </span>
              <span>
                <strong>Network Environment</strong>
                <small id="network-summary">1000ms / 20Mbps / 0% loss</small>
              </span>
            </span>
            <label className="network-range" htmlFor="network-loss">
              <span>
                <span>Loss</span>
                <strong id="network-loss-label">0%</strong>
              </span>
              <input id="network-loss" type="range" min="0" max="40" step="5" defaultValue="0" />
            </label>
            <label className="network-range" htmlFor="network-bandwidth">
              <span>
                <span>Bandwidth</span>
                <strong id="network-bandwidth-label">20Mbps</strong>
              </span>
              <input id="network-bandwidth" type="range" min="0.5" max="100" step="0.5" defaultValue="20" />
            </label>
            <label className="network-range" htmlFor="network-delay">
              <span>
                <span>Delay</span>
                <strong id="network-delay-label">1000ms</strong>
              </span>
              <input id="network-delay" type="range" min="50" max="2500" step="50" defaultValue="1000" />
            </label>
          </div>
          <div className="stage-controls" aria-label="Debugger controls">
            <div className="control-timer" aria-live="polite">
              <span>Global Timer</span>
              <strong id="global-timer">0ms</strong>
            </div>
            <div id="module-state" className="module-state" aria-live="polite">
              loading wasm
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
        </div>

        <section className="packet-stage" aria-label="QUIC packet exchange">
          <div className="stage-node stage-client">
            <span>C</span>
            <strong>Client</strong>
            <small>browser endpoint</small>
          </div>

          <div id="packet-rail" className="packet-rail">
            <span id="relay-timer-label" className="relay-timer-label">
              relay delay: 1000ms
            </span>
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
        </section>

        <section className="workbench-results" aria-label="Result Section">
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

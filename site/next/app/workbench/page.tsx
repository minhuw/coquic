import type { Metadata } from 'next';
import Script from 'next/script';
import { Gauge, Info, ListChecks, Pause, Play, StepForward, X } from 'lucide-react';

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
  ['multiplexing', 'Multiplexing'],
  ['retry', 'Retry'],
  ['resumption', 'Resumption'],
  ['zerortt', '0-RTT'],
  ['v2', 'Version 2'],
  ['connectionmigration', 'Connection Migration'],
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
    <section
      className={`endpoint ${prefix}`}
      id={`workbench-panel-${prefix}`}
      data-workbench-panel={prefix}
      aria-labelledby={`${prefix}-panel-title`}
    >
      <div className="endpoint-head">
        <div className="role">{prefix === 'client' ? 'C' : 'S'}</div>
        <div className="endpoint-title">
          <h2 id={`${prefix}-panel-title`}>{endpoint.label}</h2>
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
        <div
          id={`${prefix}-packet-spaces`}
          className="diag-table-wrap packet-space-table-wrap"
          role="region"
          aria-label={`${endpoint.label} packet spaces`}
          tabIndex={0}
        />
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
        <div
          id={`${prefix}-streams`}
          className="diag-table-wrap"
          role="region"
          aria-label={`${endpoint.label} streams`}
          tabIndex={0}
        />
      </div>
    </section>
  );
}

export default function WorkbenchPage() {
  return (
    <main className="coquic-page workbench-page" id="workbench-page" data-workbench-view="client">
      <PageHeader eyebrow="wasm QUIC laboratory" title="CoQUIC Protocol Workbench" variant="tool" />

      <div className="scenario-toolbar" aria-label="Interop case controls">
        <div className="scenario-control">
          <label className="scenario-label" htmlFor="scenario-preset">
            <span className="control-icon" aria-hidden="true">
              <ListChecks />
            </span>
            <span>Interop Scenario</span>
          </label>
          <span className="scenario-select-row">
            <select id="scenario-preset" className="scenario-select" defaultValue="transfer">
              {interopPresets.map(([value, label]) => (
                <option value={value} key={value}>
                  {label}
                </option>
              ))}
            </select>
            <button
              className="scenario-info"
              type="button"
              aria-label="Selected interop case details"
              aria-describedby="scenario-summary"
            >
              <Info />
              <span id="scenario-summary" className="scenario-summary" role="tooltip">
                Stream transfer with packet inspection.
              </span>
            </button>
          </span>
          <div className="stage-controls" aria-label="Debugger controls">
            <button id="start" className="control-button" type="button" aria-label="Start protocol exchange">
              <span className="control-icon" aria-hidden="true">
                <Play />
              </span>
              <span id="start-label" className="control-label">
                Start
              </span>
            </button>
            <button id="stop" className="control-button" type="button" aria-label="Pause protocol exchange">
              <span className="control-icon" aria-hidden="true">
                <Pause />
              </span>
              <span className="control-label">Pause</span>
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
        <div className="network-control" aria-label="Network environment">
          <span className="network-control-head">
            <span className="control-icon" aria-hidden="true">
              <Gauge />
            </span>
            <span>
              <strong>Network Context</strong>
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
      </div>

      <div className="visualization-status" aria-label="Protocol status">
        <div className="control-timer" aria-live="polite">
          <span>Global Timer</span>
          <strong id="global-timer">0ms</strong>
        </div>
        <div id="module-state" className="module-state" aria-live="polite">
          loading wasm
        </div>
      </div>

      <section className="packet-stage-shell" aria-labelledby="packet-stage-title">
        <header className="workbench-section-heading">
          <div>
            <span className="workbench-kicker">Live topology</span>
            <h2 id="packet-stage-title">Packet Exchange</h2>
          </div>
          <span className="workbench-section-meta">client to server / server to client</span>
        </header>

        <div className="packet-stage" aria-label="QUIC packet exchange">
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
            </div>
            <div className="packet-lane s2c">
              <span className="pipe-back" aria-hidden="true" />
              <span className="pipe-front" aria-hidden="true" />
            </div>
          </div>

          <div className="stage-node stage-server">
            <span>S</span>
            <strong>Server</strong>
            <small>browser endpoint</small>
          </div>
        </div>
      </section>

      <section className="workbench-results" aria-label="Result Section">
        <div className="workbench-view-tabs" id="workbench-view-tabs" role="tablist" aria-label="Workbench view">
          {(['client', 'server', 'trace', 'packets'] as const).map((view, index) => (
            <button
              id={`workbench-tab-${view}`}
              className="workbench-view-tab"
              type="button"
              role="tab"
              aria-controls={`workbench-panel-${view}`}
              aria-selected={index === 0 ? 'true' : 'false'}
              tabIndex={index === 0 ? 0 : -1}
              data-workbench-view={view}
              key={view}
            >
              {view === 'trace' ? 'Trace' : view === 'packets' ? 'Packets' : view === 'client' ? 'Client' : 'Server'}
            </button>
          ))}
        </div>

        <section className="workbench" aria-label="Endpoint diagnostics">
          <div className="endpoint-grid">
            {endpoints.map((endpoint) => (
              <EndpointPanel endpoint={endpoint} key={endpoint.key} />
            ))}
          </div>
        </section>

        <section
          className="timeline"
          id="workbench-panel-trace"
          data-workbench-panel="trace"
          aria-labelledby="workbench-trace-title"
        >
          <div className="panel-head">
            <div>
              <span className="workbench-kicker">Runtime trace</span>
              <h2 id="workbench-trace-title">Datagrams And Events</h2>
            </div>
          </div>
          <div
            id="log"
            className="log"
            role="log"
            aria-label="Datagram and event trace"
            aria-live="polite"
            tabIndex={0}
          />
        </section>

        <section
          className="packet-inspector"
          id="workbench-panel-packets"
          data-workbench-panel="packets"
          aria-label="Packet capture inspector"
        >
          <div className="capture-panel">
            <div className="panel-head">
              <div>
                <span className="workbench-kicker">Wire evidence</span>
                <h2>Packet Log</h2>
              </div>
              <div className="panel-actions">
                <button id="download-pcap" className="panel-button" type="button" disabled>
                  Download PCAP
                </button>
                <span id="packet-count">0 captured</span>
              </div>
            </div>
            <div id="packet-list" className="packet-list" role="region" aria-label="Captured packets" tabIndex={0} />
          </div>

          <span id="packet-selected" hidden>
            none selected
          </span>
          <div id="packet-detail" hidden />
        </section>
      </section>

      <dialog id="packet-modal" className="modal-backdrop" aria-labelledby="packet-modal-title">
        <div className="packet-modal">
          <div className="modal-head">
            <div>
              <h2 id="packet-modal-title">Packet Details</h2>
              <span id="packet-modal-selected">none selected</span>
            </div>
            <button id="packet-modal-close" className="modal-close" type="button" aria-label="Close packet details">
              <X aria-hidden="true" className="size-4" />
            </button>
          </div>
          <div
            id="packet-modal-detail"
            className="packet-detail modal-detail"
            role="region"
            aria-label="Selected packet detail"
            tabIndex={0}
          >
            <p className="empty-detail">
              Select a packet to inspect its QUIC header, protected payload, and raw bytes.
            </p>
          </div>
        </div>
      </dialog>

      <Script src="/quic-demo.js" strategy="afterInteractive" type="module" />
    </main>
  );
}

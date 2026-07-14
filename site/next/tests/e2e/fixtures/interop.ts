import type { Page } from '@playwright/test';

type InteropResult = 'succeeded' | 'unsupported' | 'peer_broken' | 'known_peer_broken' | 'failed';

type InteropRow = {
  client: string;
  server: string;
  name: string;
  result: InteropResult;
  details?: string;
  known_broken?: {
    peer: string;
    role: string;
    case: string;
    failed_supported_peers: number;
    supported_peers: number;
    unsupported_peers: number;
    source: string;
    run: string;
  };
};

function row(
  server: string,
  client: string,
  name: string,
  result: InteropResult,
  extra: Pick<InteropRow, 'details' | 'known_broken'> = {},
): InteropRow {
  return { server, client, name, result, ...extra };
}

export const interopSnapshot = {
  schema_version: 1,
  generated_at: '2026-07-14T12:34:56Z',
  event_name: 'interop-fixture',
  commit: 'fixture-011',
  sources: [
    { label: 'quinn', path: 'interop-results.json', server: 'quinn', client: 'coquic' },
    { label: 'picoquic', path: 'interop-results.json', server: 'coquic', client: 'picoquic' },
    { label: 'quic-go', path: 'interop-results.json', server: 'coquic', client: 'quic-go' },
    { label: 'filtered-peer-lane', path: 'interop-results.json', server: 'picoquic', client: 'quinn' },
  ],
  rows: [
    row('quinn', 'coquic', 'retry', 'failed', {
      known_broken: {
        peer: 'quinn',
        role: 'server',
        case: 'retry',
        failed_supported_peers: 1,
        supported_peers: 1,
        unsupported_peers: 0,
        source: 'upstream interop',
        run: 'fixture',
      },
    }),
    row('quinn', 'coquic', 'blackhole', 'peer_broken'),
    row('quinn', 'coquic', 'transfer', 'unsupported'),
    row('quinn', 'coquic', 'handshake', 'succeeded'),

    row('coquic', 'picoquic', 'retry', 'unsupported'),
    row('coquic', 'picoquic', 'blackhole', 'peer_broken'),
    row('coquic', 'picoquic', 'keyupdate', 'known_peer_broken', { details: 'known peer issue' }),
    row('coquic', 'picoquic', 'transfer', 'succeeded'),
    row('coquic', 'picoquic', 'handshake', 'failed', { details: 'fixture packet loss' }),

    row('coquic', 'quic-go', 'retry', 'failed', {
      known_broken: {
        peer: 'quic-go',
        role: 'client',
        case: 'retry',
        failed_supported_peers: 1,
        supported_peers: 1,
        unsupported_peers: 0,
        source: 'upstream interop',
        run: 'fixture',
      },
    }),
    row('coquic', 'quic-go', 'blackhole', 'known_peer_broken'),
    row('coquic', 'quic-go', 'keyupdate', 'peer_broken'),
    row('coquic', 'quic-go', 'transfer', 'unsupported'),
    row('coquic', 'quic-go', 'handshake', 'succeeded'),

    row('picoquic', 'quinn', 'handshake', 'failed', { details: 'filtered lane' }),
  ],
};

export async function installInteropFixture(page: Page, snapshot = interopSnapshot) {
  const requests: string[] = [];
  await page.route('**/interop-results.json', async (route) => {
    requests.push(new URL(route.request().url()).pathname);
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify(snapshot),
    });
  });
  return requests;
}

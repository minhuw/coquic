import type { Page, Route } from '@playwright/test';

export type PerformanceFixtureOptions = {
  current?: 'valid' | 'empty' | 'missing' | 'malformed';
  history?: 'indexed' | 'legacy' | 'missing' | 'malformed' | 'empty';
  historyDelayMs?: number;
};

type FixtureResponse = {
  body: unknown;
  status?: number;
  delayMs?: number;
};

const sources = [
  { label: 'coquic', path: 'perf-results.json', library_version: '0.4.0' },
  { label: 'coquic-rust', path: 'perf-results.json', library_version: '0.4.0' },
  { label: 'quic-go', path: 'perf-results.json', library_version: '0.55.0' },
  { label: 'quinn', path: 'perf-results.json', library_version: '0.11.7', missing: true },
];

function makeRow(
  implementation: string,
  mode: string,
  value: number,
  extras: Record<string, unknown> = {},
) {
  return {
    implementation,
    mode,
    status: 'ok',
    throughput_mib_per_s: mode === 'bulk' ? value : 0,
    requests_per_s: mode === 'bulk' ? 0 : value,
    elapsed_ms: 42,
    p50_us: 180,
    p99_us: 620,
    ...extras,
  };
}

const detailMetadata = {
  utilization: {
    client: {
      cpu_utilization_avg: 0.12,
      cpu_utilization_max: 0.2,
      cpu_percent_avg: 12,
      cpu_percent_max: 20,
      memory_bytes_avg: 1_048_576,
      memory_bytes_max: 2_097_152,
      samples: 8,
    },
    server: {
      cpu_utilization_avg: 0.08,
      cpu_utilization_max: 0.16,
      cpu_percent_avg: 8,
      cpu_percent_max: 16,
      memory_bytes_avg: 524_288,
      memory_bytes_max: 1_048_576,
      samples: 8,
    },
  },
  profiles: {
    client: { svg_file: 'coquic-client.svg', log_file: 'coquic-client.perf.log' },
    server: { svg_file: 'coquic-server.svg', log_file: 'coquic-server.perf.log' },
  },
};

export function makePerformanceSnapshot(
  date = '2026-07-14',
  generatedAt = '2026-07-14T12:00:00Z',
  multiplier = 1,
) {
  return {
    schema_version: 1,
    generated_at: generatedAt,
    event_name: 'nightly-performance',
    commit: 'abc1234',
    sources,
    rows: [
      makeRow('coquic', 'bulk', 120 * multiplier, { congestion_control: 'cubic', ...detailMetadata }),
      makeRow('coquic', 'bulk', 110 * multiplier, { congestion_control: 'bbr' }),
      makeRow('coquic-rust', 'bulk', 96 * multiplier),
      makeRow('quic-go', 'bulk', 82 * multiplier),
      makeRow('coquic', 'rr', 360 * multiplier, { congestion_control: 'cubic' }),
      makeRow('coquic-rust', 'rr', 300 * multiplier),
      makeRow('quic-go', 'rr', 250 * multiplier),
      makeRow('coquic', 'persistent-rr', 410 * multiplier, { congestion_control: 'cubic' }),
      makeRow('coquic-rust', 'persistent-rr', 350 * multiplier),
      makeRow('quic-go', 'persistent-rr', 290 * multiplier),
      makeRow('coquic', 'crr', 190 * multiplier, { congestion_control: 'cubic' }),
      makeRow('coquic-rust', 'crr', 160 * multiplier),
      makeRow('quic-go', 'crr', 140 * multiplier),
      makeRow('quic-go', 'bulk', 0, { status: 'failed', error: 'fixture failure' }),
    ],
    date,
  };
}

export type InstalledPerformanceFixture = {
  requests: string[];
  currentSnapshot: ReturnType<typeof makePerformanceSnapshot>;
};

async function fulfill(route: Route, response: FixtureResponse) {
  if (response.delayMs) {
    await new Promise((resolve) => setTimeout(resolve, response.delayMs));
  }
  await route.fulfill({
    status: response.status ?? 200,
    contentType: 'application/json',
    body: JSON.stringify(response.body),
  });
}

function statusResponse(status: number, body = { error: 'fixture response' }): FixtureResponse {
  return { status, body };
}

export async function installPerformanceFixture(
  page: Page,
  options: PerformanceFixtureOptions = {},
): Promise<InstalledPerformanceFixture> {
  const currentMode = options.current ?? 'valid';
  const historyMode = options.history ?? 'indexed';
  const currentSnapshot = makePerformanceSnapshot();
  const historySnapshots = [
    makePerformanceSnapshot('2026-07-13', '2026-07-13T12:00:00Z', 0.9),
    makePerformanceSnapshot('2026-07-14', '2026-07-14T12:00:00Z', 1),
  ];
  const requests: string[] = [];

  page.on('request', (request) => {
    const url = new URL(request.url());
    if (url.pathname.endsWith('.json') || url.pathname.includes('/perf-artifacts/')) {
      requests.push(url.pathname);
    }
  });

  const currentResponse: FixtureResponse = currentMode === 'valid'
    ? { body: currentSnapshot }
    : currentMode === 'empty'
      ? { body: { ...currentSnapshot, rows: [] } }
      : currentMode === 'malformed'
        ? { body: { schema_version: 1, rows: 'not-an-array', sources: {} } }
        : statusResponse(503, { error: 'current benchmark unavailable' });

  const indexResponse: FixtureResponse = historyMode === 'indexed'
    ? {
      body: {
        schema_version: 1,
        generated_at: '2026-07-14T12:00:00Z',
        snapshots: historySnapshots.map((snapshot) => ({
          date: snapshot.date,
          generated_at: snapshot.generated_at,
          event_name: snapshot.event_name,
          commit: snapshot.commit,
          path: `${snapshot.date}.json`,
        })),
      },
      delayMs: options.historyDelayMs,
    }
    : historyMode === 'empty'
      ? { body: { schema_version: 1, generated_at: '2026-07-14T12:00:00Z', snapshots: [] } }
      : historyMode === 'malformed'
        ? { body: { schema_version: 1, snapshots: 'not-an-array' } }
        : statusResponse(404, { error: 'index unavailable' });

  const legacyResponse: FixtureResponse = historyMode === 'legacy'
    ? { body: { schema_version: 1, generated_at: '2026-07-14T12:00:00Z', snapshots: historySnapshots } }
    : historyMode === 'malformed'
      ? { body: { schema_version: 1, snapshots: 'not-an-array' } }
      : statusResponse(404, { error: 'legacy history unavailable' });

  await page.route('**/perf-results.json', (route) => fulfill(route, currentResponse));
  await page.route('**/perf-history/index.json', (route) => fulfill(route, indexResponse));
  await page.route('**/perf-history/2026-07-13.json', (route) => fulfill(route, {
    body: historySnapshots[0],
    delayMs: options.historyDelayMs,
  }));
  await page.route('**/perf-history/2026-07-14.json', (route) => fulfill(route, {
    body: historySnapshots[1],
    delayMs: options.historyDelayMs,
  }));
  await page.route('**/perf-history.json', (route) => fulfill(route, legacyResponse));
  await page.route('**/perf-artifacts/**', (route) => route.fulfill({
    status: 200,
    contentType: 'image/svg+xml',
    body: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20"><title>fixture flamegraph</title><rect width="20" height="20" /></svg>',
  }));

  return { requests, currentSnapshot };
}

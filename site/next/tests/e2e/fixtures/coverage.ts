export const populatedCoverage = {
  schema_version: 1,
  generated_at: '2026-07-14T12:34:56Z',
  event_name: 'push',
  commit: '012abc345def',
  report_url: './coverage/index.html',
  totals: {
    functions: { covered: 73, total: 100, percent: 73.0 },
    lines: { covered: 842, total: 1000, percent: 84.2 },
    branches: { covered: 61, total: 100, percent: 61.0 },
  },
  components: [
    {
      name: 'transport',
      metrics: {
        functions: { covered: 40, total: 50, percent: 80.0 },
        lines: { covered: 80, total: 100, percent: 80.0 },
        branches: { covered: 40, total: 50, percent: 80.0 },
      },
    },
    {
      name: 'zeta',
      metrics: {
        functions: { covered: 18, total: 30, percent: 60.0 },
        lines: { covered: 30, total: 75, percent: 40.0 },
        branches: { covered: 10, total: 25, percent: 40.0 },
      },
    },
    {
      name: 'alpha',
      metrics: {
        functions: { covered: 15, total: 20, percent: 75.0 },
        lines: { covered: 20, total: 50, percent: 40.0 },
        branches: { covered: 11, total: 25, percent: 44.0 },
      },
    },
  ],
  files: [],
  least_covered_files: [
    {
      path: 'src/transport/packet-parser-with-a-deliberately-long-file-name-that-must-wrap-without-widening-the-page.c',
      component: 'transport',
      metrics: {
        functions: { covered: 2, total: 10, percent: 20.0 },
        lines: { covered: 8, total: 40, percent: 20.0 },
        branches: { covered: 1, total: 10, percent: 10.0 },
      },
    },
    {
      path: 'src/core/second-file.c',
      component: 'core',
      metrics: {
        functions: { covered: 5, total: 10, percent: 50.0 },
        lines: { covered: 25, total: 50, percent: 50.0 },
        branches: { covered: 5, total: 10, percent: 50.0 },
      },
    },
  ],
} as const;

export const emptyCoverage = {
  ...populatedCoverage,
  generated_at: '2026-07-14T12:35:00Z',
  event_name: 'workflow_dispatch',
  commit: 'empty012',
  totals: {
    functions: { covered: 0, total: 0, percent: 100.0 },
    lines: { covered: 0, total: 0, percent: 100.0 },
    branches: { covered: 0, total: 0, percent: 100.0 },
  },
  components: [],
  files: [],
  least_covered_files: [],
} as const;

export const zeroCoverage = {
  ...populatedCoverage,
  generated_at: '2026-07-14T12:36:00Z',
  event_name: 'pull_request',
  commit: 'zero012',
  totals: {
    functions: { covered: 0, total: 10, percent: 0.0 },
    lines: { covered: 0, total: 20, percent: 0.0 },
    branches: { covered: 0, total: 8, percent: 0.0 },
  },
  components: [
    {
      name: 'zero-component',
      metrics: {
        functions: { covered: 0, total: 10, percent: 0.0 },
        lines: { covered: 0, total: 20, percent: 0.0 },
        branches: { covered: 0, total: 8, percent: 0.0 },
      },
    },
  ],
  files: [],
  least_covered_files: [
    {
      path: 'src/zero.c',
      component: 'zero-component',
      metrics: {
        functions: { covered: 0, total: 10, percent: 0.0 },
        lines: { covered: 0, total: 20, percent: 0.0 },
        branches: { covered: 0, total: 8, percent: 0.0 },
      },
    },
  ],
} as const;

export const malformedCoverage = '{"schema_version":1,"totals":';

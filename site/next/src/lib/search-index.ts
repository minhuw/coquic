import { generatedDocSearchItems } from '@/generated/site-search-docs';

export type SiteSearchKind = 'page' | 'docs' | 'tool' | 'dashboard' | 'scenario';

export type SiteSearchItem = {
  id: string;
  title: string;
  href: string;
  section: string;
  description: string;
  kind: SiteSearchKind;
  keywords: string[];
  headings?: readonly string[];
  body?: string;
};

const routeItems: SiteSearchItem[] = [
  {
    id: 'route-home',
    title: 'Home',
    href: '/',
    section: 'Project',
    description: 'CoQUIC landing page and main project entry point.',
    kind: 'page',
    keywords: ['coquic', 'prompt to packet', 'landing'],
  },
  {
    id: 'route-qa',
    title: 'Ask QUIC',
    href: '/qa',
    section: 'Specification QA',
    description: 'Ask RFC-backed QUIC questions with direct and RAG answers side by side.',
    kind: 'tool',
    keywords: ['rag', 'question', 'rfc', 'citations', 'ack', 'pto', 'loss', 'openrouter'],
  },
  {
    id: 'route-docs',
    title: 'Docs',
    href: '/docs',
    section: 'Documentation',
    description: 'Browse CoQUIC documentation and API guides.',
    kind: 'docs',
    keywords: ['documentation', 'api', 'guide', 'reference'],
  },
  {
    id: 'route-workbench',
    title: 'Protocol Workbench',
    href: '/workbench',
    section: 'WASM Lab',
    description: 'Run browser-based QUIC scenarios, inspect packets, endpoints, streams, and recovery state.',
    kind: 'tool',
    keywords: ['wasm', 'packet', 'pcap', 'handshake', 'retry', '0-rtt', 'migration', 'loss', 'debugger'],
  },
  {
    id: 'route-performance',
    title: 'Performance Comparison',
    href: '/performance',
    section: 'Benchmark',
    description: 'View LAN benchmark bar plots and daily performance trends.',
    kind: 'dashboard',
    keywords: ['lan', 'benchmark', 'bulk', 'crr', 'rr', 'throughput', 'latency', 'goodput'],
  },
  {
    id: 'route-interop',
    title: 'Interop Matrix',
    href: '/interop',
    section: 'Development',
    description: 'Inspect compatibility results across CoQUIC interop cases and peer implementations.',
    kind: 'dashboard',
    keywords: ['interop', 'compatibility', 'quic-go', 'quinn', 'picoquic', 'pass', 'fail', 'skip'],
  },
  {
    id: 'route-coverage',
    title: 'Coverage Report',
    href: '/coverage',
    section: 'Development',
    description: 'Review LLVM source coverage totals, component coverage, and lowest-covered files.',
    kind: 'dashboard',
    keywords: ['coverage', 'llvm', 'lines', 'branches', 'tests'],
  },
];

const scenarioItems: SiteSearchItem[] = [
  {
    id: 'scenario-handshake',
    title: 'Handshake Scenario',
    href: '/workbench',
    section: 'Workbench Scenario',
    description: 'Open the protocol workbench to inspect Initial, Handshake, and 1-RTT setup.',
    kind: 'scenario',
    keywords: ['initial', 'tls', 'crypto', 'packet spaces'],
  },
  {
    id: 'scenario-retry',
    title: 'Retry Scenario',
    href: '/workbench',
    section: 'Workbench Scenario',
    description: 'Open the workbench and choose Retry to inspect address validation behavior.',
    kind: 'scenario',
    keywords: ['retry', 'address validation', 'token', 'anti amplification'],
  },
  {
    id: 'scenario-zerortt',
    title: '0-RTT Scenario',
    href: '/workbench',
    section: 'Workbench Scenario',
    description: 'Open the workbench and choose 0-RTT to inspect early data and resumption behavior.',
    kind: 'scenario',
    keywords: ['zero rtt', '0-rtt', 'early data', 'resumption', 'session ticket'],
  },
  {
    id: 'scenario-key-update',
    title: 'Key Update Scenario',
    href: '/workbench',
    section: 'Workbench Scenario',
    description: 'Open the workbench and choose Key Update to inspect native 1-RTT key updates.',
    kind: 'scenario',
    keywords: ['key update', 'secrets', '1-rtt', 'packet protection'],
  },
  {
    id: 'scenario-migration',
    title: 'Connection Migration Scenario',
    href: '/workbench',
    section: 'Workbench Scenario',
    description: 'Open the workbench and choose Connection Migration to inspect path changes.',
    kind: 'scenario',
    keywords: ['migration', 'path validation', 'new path', 'connection id'],
  },
];

export const siteSearchItems: SiteSearchItem[] = [
  ...routeItems,
  ...generatedDocSearchItems,
  ...scenarioItems,
];

export type DocSlug = string[];

export type DocNavItem = {
  slug: DocSlug;
  href: string;
  label: string;
  file: string;
  section: string;
  level?: 0 | 1;
};

export const docItems: DocNavItem[] = [
  { slug: [], href: '/docs', label: 'Overview', file: 'README.md', section: 'Start' },
  { slug: ['api', 'public-api'], href: '/docs/api/public-api', label: 'Public API', file: 'api/public-api.md', section: 'API Surface' },
  { slug: ['api', 'core'], href: '/docs/api/core', label: 'Core API', file: 'api/core.md', section: 'API Surface', level: 1 },
  { slug: ['api', 'quic'], href: '/docs/api/quic', label: 'QUIC Facade API', file: 'api/quic.md', section: 'API Surface', level: 1 },
  { slug: ['api', 'http3'], href: '/docs/api/http3', label: 'HTTP/3 API', file: 'api/http3.md', section: 'API Surface', level: 1 },
  { slug: ['api', 'integration'], href: '/docs/api/integration', label: 'Runtime Integration', file: 'api/integration.md', section: 'Runtime' },
];

import { chromium, type FullConfig } from '@playwright/test';

import { docItems } from '../../src/lib/doc-items';

const applicationRoutes = [
  '/',
  ...docItems.map(({ href }) => href),
  '/blog',
  '/blog/coquic-steward',
  '/blog/why-coquic',
  '/qa',
  '/transcript',
  '/workbench',
  '/duvet',
  '/performance',
  '/perf-comparison',
  '/interop',
  '/interop-results',
  '/coverage',
  '/coverage-results',
  '/steward',
  '/steward/planner',
  '/steward/tasks/task-20260713115945-a1b2c3d4',
];

export default async function globalSetup(config: FullConfig) {
  const baseURL = config.projects[0]?.use.baseURL;
  if (typeof baseURL !== 'string') throw new Error('Playwright prewarm requires a string baseURL');

  const browser = await chromium.launch();
  const page = await browser.newPage();

  try {
    for (const route of applicationRoutes) {
      const response = await page.goto(new URL(route, baseURL).href, { waitUntil: 'networkidle' });
      if (!response?.ok()) {
        throw new Error(`Playwright prewarm failed for ${route}: ${response?.status() ?? 'no response'}`);
      }
      await page.locator('html[data-coquic-hydrated="true"]').waitFor();
    }
  } finally {
    await browser.close();
  }
}

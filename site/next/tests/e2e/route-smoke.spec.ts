import { expect, test } from '@playwright/test';

import { docItems } from '../../src/lib/doc-items';
import {
  designViewports,
  expectLocalScrollRegion,
  expectNoGlobalOverflow,
  expectNoSeriousAxeViolations,
} from './helpers/design-system';

type RouteContract = {
  heading: string | RegExp;
  headingLevel?: 1 | 2;
  path: string;
  title: string;
};

const docHeadings: Record<string, string> = {
  '/docs': 'CoQUIC Documentation',
  '/docs/api/public-api': 'Public API',
  '/docs/api/core': 'Core API',
  '/docs/api/quic': 'QUIC Facade API',
  '/docs/api/http3': 'HTTP/3 API',
  '/docs/api/c-ffi': 'C FFI API',
  '/docs/api/c-ffi-reference': 'C FFI Reference',
  '/docs/api/rust-wrapper': 'Rust Wrappers',
  '/docs/api/javascript-wrapper': 'JavaScript Wrapper',
  '/docs/api/python-wrapper': 'Python Wrapper',
  '/docs/api/go-wrapper': 'Go Wrapper',
  '/docs/api/integration': 'Runtime Integration',
};

const docsRoutes: RouteContract[] = docItems.map(({ href }) => {
  const heading = docHeadings[href];
  return {
    heading,
    path: href,
    title: href === '/docs' ? heading : `${heading} | CoQUIC Documentation`,
  };
});

const routeInventory: RouteContract[] = [
  { path: '/', title: 'CoQUIC: AI-Generated QUIC, From Prompt to Packet', heading: /CoQUIC/ },
  ...docsRoutes,
  { path: '/blog', title: 'CoQUIC Blog', heading: 'CoQUIC Blog' },
  { path: '/blog/coquic-steward', title: 'CoQUIC Steward: Letting an Agent Maintain the Repository | CoQUIC Blog', heading: 'CoQUIC Steward: Letting an Agent Maintain the Repository' },
  { path: '/blog/why-coquic', title: 'Why CoQUIC? | CoQUIC Blog', heading: 'Why CoQUIC?' },
  { path: '/qa', title: 'CoQUIC QUIC QA', heading: 'CoQUIC Specification QA' },
  { path: '/transcript', title: 'CoQUIC Transcript Dataset', heading: 'CoQUIC Transcript Dataset' },
  { path: '/workbench', title: 'CoQUIC Protocol Workbench', heading: 'CoQUIC Protocol Workbench' },
  { path: '/duvet', title: 'CoQUIC Duvet RFC Compliance', heading: 'CoQUIC Duvet Report' },
  { path: '/performance', title: 'CoQUIC Performance Comparison', heading: 'CoQUIC Performance Comparison' },
  { path: '/perf-comparison', title: 'CoQUIC Performance Comparison', heading: 'CoQUIC Performance Comparison' },
  { path: '/interop', title: 'CoQUIC Interop Results', heading: 'CoQUIC Interop Matrix' },
  { path: '/interop-results', title: 'CoQUIC Interop Results', heading: 'CoQUIC Interop Matrix' },
  { path: '/coverage', title: 'CoQUIC Coverage Results', heading: 'CoQUIC Coverage Report' },
  { path: '/coverage-results', title: 'CoQUIC Coverage Results', heading: 'CoQUIC Coverage Report' },
  { path: '/steward', title: 'CoQUIC Steward', heading: 'CoQUIC Steward', headingLevel: 2 },
  { path: '/steward/planner', title: 'Planner history | CoQUIC Steward', heading: 'Planner history' },
  {
    path: '/steward/tasks/task-20260713115945-a1b2c3d4',
    title: 'task-20260713115945-a1b2c3d4 | CoQUIC Steward',
    heading: 'Implement dashboard contract',
  },
];

test.describe('route identity', () => {
  test.describe.configure({ mode: 'serial' });

  for (const route of routeInventory) {
    test(`${route.path} exposes its stable identity`, async ({ page }) => {
      const response = await page.goto(route.path);
      expect(response?.ok(), `${route.path} returned ${response?.status() ?? 'no response'}`).toBe(true);
      await expect(page).toHaveTitle(route.title);
      await expect(page.getByRole('heading', { name: route.heading, level: route.headingLevel ?? 1 })).toBeVisible();
      await expect(page.locator('body > main')).toHaveCount(1);
    });
  }
});

for (const [canonical, alias] of [
  ['/perf-comparison', '/performance'],
  ['/interop-results', '/interop'],
  ['/coverage-results', '/coverage'],
] as const) {
  test(`${alias} matches ${canonical} route identity`, async ({ page }) => {
    await page.goto(canonical);
    const canonicalIdentity = {
      heading: await page.getByRole('heading', { level: 1 }).innerText(),
      title: await page.title(),
    };
    await page.goto(alias);
    await expect(page).toHaveTitle(canonicalIdentity.title);
    await expect(page.getByRole('heading', { name: canonicalIdentity.heading, level: 1 })).toBeVisible();
  });
}

test('home shell fits the configured project viewport', async ({ page }, testInfo) => {
  const viewport = testInfo.project.name === 'mobile' ? designViewports.phone375 : designViewports.wide;
  await page.setViewportSize(viewport);
  await page.goto('/');
  await expectNoGlobalOverflow(page);
  await expectNoSeriousAxeViolations(page, 'main');
});

test('retained Steward task exposes a named local scroll region', async ({ page }) => {
  await page.goto('/steward/tasks/task-20260713115945-a1b2c3d4');
  await expect(page.getByRole('heading', { name: 'Implement dashboard contract' })).toBeVisible();
  await expectLocalScrollRegion(page, '.pipeline-graph');
});

test.fixme('Steward task has no nested main landmark after plan 018', async ({ page }) => {
  await page.goto('/steward/tasks/task-20260713115945-a1b2c3d4');
  await expect(page.locator('main main')).toHaveCount(0);
});

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
  { path: '/steward', title: 'CoQUIC Steward', heading: 'CoQUIC Steward' },
  { path: '/steward/planner', title: 'Planner history | CoQUIC Steward', heading: 'Planner history' },
  {
    path: '/steward/tasks/task-20260713115945-a1b2c3d4',
    title: 'task-20260713115945-a1b2c3d4 | CoQUIC Steward',
    heading: 'Implement dashboard contract',
  },
];

const sharedHeaderRoutes = new Map<string, string>([
  ...docsRoutes.map(({ path }) => [path, 'editorial'] as const),
  ['/blog', 'editorial'],
  ['/qa', 'tool'],
  ['/transcript', 'data'],
  ['/workbench', 'tool'],
  ['/duvet', 'evidence'],
  ['/performance', 'evidence'],
  ['/perf-comparison', 'evidence'],
  ['/interop', 'evidence'],
  ['/interop-results', 'evidence'],
  ['/coverage', 'evidence'],
  ['/coverage-results', 'evidence'],
  ['/steward', 'operations'],
  ['/steward/planner', 'operations'],
]);

test.describe('route identity', () => {
  test.describe.configure({ mode: 'serial' });

  for (const route of routeInventory) {
    test(`${route.path} exposes its stable identity`, async ({ page }) => {
      const response = await page.goto(route.path);
      expect(response?.ok(), `${route.path} returned ${response?.status() ?? 'no response'}`).toBe(true);
      await expect(page).toHaveTitle(route.title);
      await expect(page.getByRole('heading', { name: route.heading, level: route.headingLevel ?? 1 })).toBeVisible();
      await expect(page.locator('main.coquic-page')).toHaveCount(1);
      await expect(page.getByRole('navigation', { name: 'Demo views' })).toHaveCount(1);
      await expect(page.getByRole('link', { name: 'Skip to content' })).toHaveCount(1);
      await expect(page.getByRole('contentinfo')).toHaveCount(1);
      const headerVariant = sharedHeaderRoutes.get(route.path);
      if (headerVariant) {
        const header = page.locator('main .page-header');
        await expect(header).toHaveCount(1);
        await expect(header).toHaveAttribute('data-page-header-variant', headerVariant);
        await expect(header.locator('.page-header__eyebrow-marker')).toHaveCount(1);
        await expect(header.locator('.page-header__art')).toHaveCount(0);
      }
    });
  }
});

test('shared page header keeps route context on the page content axis', async ({ page }) => {
  await page.goto('/docs');

  const header = page.locator('main .page-header');
  const viewportWidth = page.viewportSize()?.width ?? 0;
  const geometry = await header.evaluate((element) => {
    const headerBounds = element.getBoundingClientRect();
    const contextBounds = element.querySelector<HTMLElement>('.page-header__context')?.getBoundingClientRect();
    const titleBounds = element.querySelector<HTMLElement>('.page-title')?.getBoundingClientRect();
    return {
      background: getComputedStyle(element).backgroundColor,
      contextBottom: contextBounds?.bottom ?? 0,
      contextLeft: contextBounds?.left ?? 0,
      headerHeight: headerBounds.height,
      titleFontSize: Number.parseFloat(getComputedStyle(element.querySelector('.page-title')!).fontSize),
      titleLeft: titleBounds?.left ?? 0,
      titleTop: titleBounds?.top ?? 0,
    };
  });

  expect(geometry.background).toBe('rgba(0, 0, 0, 0)');
  expect(geometry.titleFontSize).toBeGreaterThanOrEqual(28);
  expect(Math.abs(geometry.contextLeft - geometry.titleLeft)).toBeLessThanOrEqual(1);
  expect(geometry.contextBottom).toBeLessThanOrEqual(geometry.titleTop);
  await expect(header.locator('.page-header__art')).toHaveCount(0);
  if (viewportWidth >= 768) {
    expect(geometry.headerHeight).toBeLessThan(190);
  } else {
    expect(geometry.headerHeight).toBeLessThan(260);
  }
  await expectNoGlobalOverflow(page);
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

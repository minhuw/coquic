import AxeBuilder from '@axe-core/playwright';
import { expect, test } from '@playwright/test';

import {
  designViewports,
  expectLocalScrollRegion,
  expectNoGlobalOverflow,
  setStoredTheme,
  tabUntilFocused,
} from './helpers/design-system';

const editorialRoutes = [
  { path: '/docs', kind: 'docs' },
  { path: '/docs/api/c-ffi-reference', kind: 'docs' },
  { path: '/blog/why-coquic', kind: 'blog' },
  { path: '/blog/coquic-steward', kind: 'blog' },
] as const;

const editorialViewports = [
  ['320', designViewports.phone320],
  ['1440', designViewports.wide],
] as const;

const editorialThemes = ['light', 'dark'] as const;

async function waitForScrollRegionMeasurement(page: Parameters<typeof setStoredTheme>[0]) {
  await page.waitForFunction(() => {
    const regions = Array.from(document.querySelectorAll<HTMLElement>('[data-scroll-region="true"]'));
    return regions.every((region) => region.scrollWidth <= region.clientWidth + 1 || region.dataset.overflow === 'true');
  });
}

async function expectNoEditorialAxeViolations(page: Parameters<typeof setStoredTheme>[0]) {
  const results = await new AxeBuilder({ page }).include('main').analyze();
  expect(
    results.violations.filter((violation) => violation.impact === 'serious' || violation.impact === 'critical'),
  ).toEqual([]);
  expect(results.violations.filter((violation) => violation.id === 'scrollable-region-focusable')).toEqual([]);
}

async function installClipboardProbe(page: Parameters<typeof setStoredTheme>[0]) {
  await page.addInitScript(() => {
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: {
        writeText: async (value: string) => {
          if (window.localStorage.getItem('coquic-playwright-clipboard') === 'reject') {
            throw new Error('clipboard permission denied');
          }
          window.localStorage.setItem('coquic-playwright-copied', value);
        },
      },
    });
  });
}

test.describe('editorial primitives', () => {
  for (const route of editorialRoutes) {
    for (const [viewportName, viewport] of editorialViewports) {
      for (const theme of editorialThemes) {
        test(`${route.path} stays editorially bounded at ${viewportName}px in ${theme} theme`, async ({ page }, testInfo) => {
          await page.setViewportSize(viewport);
          await setStoredTheme(page, theme);
          await page.goto(route.path);

          await expect(page.locator('html')).toHaveAttribute('data-theme', theme);
          await expect(page.locator('main h1')).toHaveCount(1);
          await expect(page.locator('.article-content')).toHaveCount(1);
          await waitForScrollRegionMeasurement(page);
          await expectNoGlobalOverflow(page);
          await expectNoEditorialAxeViolations(page);

          const headings = page.locator('.article-content h2[id], .article-content h3[id]');
          if ((await headings.count()) > 0) {
            const heading = headings.first();
            const permalink = heading.locator('..').locator('.anchored-heading__permalink');
            await expect(permalink).toHaveCount(1);
            if (testInfo.project.name === 'mobile') {
              await expect(permalink).toBeVisible();
              const permalinkBounds = await permalink.boundingBox();
              expect(permalinkBounds?.width).toBeGreaterThanOrEqual(44);
              expect(permalinkBounds?.height).toBeGreaterThanOrEqual(44);
            }
            await heading.hover();
            await expect(permalink).toBeVisible();
            await expect(permalink).toHaveAccessibleName(/Permalink to/);
            await permalink.focus();
            await expect(permalink).toBeFocused();
          }

          if (route.kind === 'blog') {
            const panels = page.locator('[data-blog-language-panel]');
            await expect(panels).toHaveCount(2);
            const englishPanel = page.locator('[data-blog-language-panel="en"]');
            const chinesePanel = page.locator('[data-blog-language-panel="zh"]');
            await expect(englishPanel).toBeVisible();
            await expect(chinesePanel).toBeHidden();
            await expect(englishPanel).toHaveAttribute('lang', 'en');
            await expect(chinesePanel).toHaveAttribute('lang', 'zh-CN');
            const images = page.locator('.article-content img');
            const imageCount = await images.count();
            if (route.path === '/blog/coquic-steward') expect(imageCount).toBeGreaterThan(0);
            for (let imageIndex = 0; imageIndex < imageCount; imageIndex += 1) {
              await expect(images.nth(imageIndex)).toHaveAttribute('alt', /\S/);
            }
          }
        });
      }
    }
  }

  test('C FFI code regions are named, locally scrollable, and keyboard reachable', async ({ page }) => {
    await page.setViewportSize(designViewports.phone320);
    await setStoredTheme(page, 'light');
    await installClipboardProbe(page);
    await page.goto('/docs/api/c-ffi-reference');
    await waitForScrollRegionMeasurement(page);

    const codeRegions = page.locator('.editorial-code-scroll[data-scroll-region="true"]');
    await expect(codeRegions).not.toHaveCount(0);
    const overflowingCodeIndex = await codeRegions.evaluateAll((regions) =>
      regions.findIndex((region) => region.scrollWidth > region.clientWidth + 1),
    );
    expect(overflowingCodeIndex, 'expected a long C FFI code block at 320px').toBeGreaterThanOrEqual(0);
    const codeRegion = codeRegions.nth(overflowingCodeIndex);
    await expectLocalScrollRegion(page, `.editorial-code-scroll[data-scroll-region="true"] >> nth=${overflowingCodeIndex}`);
    await tabUntilFocused(page, codeRegion);
    const beforeScroll = await codeRegion.evaluate((region) => region.scrollLeft);
    await page.keyboard.press('ArrowRight');
    const afterScroll = await codeRegion.evaluate((region) => region.scrollLeft);
    expect(afterScroll).toBeGreaterThanOrEqual(beforeScroll);

    const codeBlock = page.locator('.editorial-code-block').first();
    const copyButton = codeBlock.getByRole('button');
    const copyStatus = codeBlock.getByRole('status');
    await expect(copyButton).toHaveAccessibleName('Copy code');
    await copyButton.focus();
    await expect(copyButton).toBeFocused();
    await copyButton.click();
    await expect(copyButton).toHaveAccessibleName('Code copied');
    await expect(copyStatus).toHaveText('Copied to clipboard.');

    await page.evaluate(() => window.localStorage.setItem('coquic-playwright-clipboard', 'reject'));
    await copyButton.click();
    await expect(copyButton).toHaveAccessibleName('Copy failed');
    await expect(copyStatus).toHaveText('Unable to copy code. Try again.');
    await expectNoEditorialAxeViolations(page);
  });

  test('editorial table regions retain table semantics when present', async ({ page }) => {
    await page.setViewportSize(designViewports.phone320);
    await setStoredTheme(page, 'dark');
    await page.goto('/blog/why-coquic');

    const tableRegions = page.locator('.editorial-table-region');
    if ((await tableRegions.count()) === 0) return;

    const tableRegion = tableRegions.first();
    await expect(tableRegion).toHaveAccessibleName('Data table');
    await expect(tableRegion.locator('table')).toHaveCount(1);
    await expect(tableRegion.locator('thead')).toHaveCount(1);
    await expect(tableRegion.locator('tbody')).toHaveCount(1);
    await expectLocalScrollRegion(page, '.editorial-table-region');
    await tableRegion.focus();
    await expect(tableRegion).toBeFocused();
  });
});

import AxeBuilder from '@axe-core/playwright';
import { expect, test } from '@playwright/test';

import { docItems } from '../../src/lib/doc-items';
import {
  designViewports,
  expectLocalScrollRegion,
  expectNoGlobalOverflow,
  setStoredTheme,
  waitForVisualAssets,
} from './helpers/design-system';

const docs = docItems.map((item) => ({
  ...item,
  title: item.href === '/docs' ? 'CoQUIC Documentation' : `${item.label} | CoQUIC Documentation`,
}));
const themes = ['light', 'dark'] as const;

async function prepareVisualSnapshot(page: Parameters<typeof setStoredTheme>[0]) {
  await waitForVisualAssets(page);
}

async function expectDocsAxe(page: Parameters<typeof setStoredTheme>[0]) {
  await page.waitForFunction(() => {
    const regions = Array.from(document.querySelectorAll<HTMLElement>('[data-scroll-region="true"]'));
    return regions.every((region) => region.scrollWidth <= region.clientWidth + 1 || region.dataset.overflow === 'true');
  });
  const results = await new AxeBuilder({ page }).include('main').analyze();
  expect(results.violations.filter((violation) => violation.impact === 'serious' || violation.impact === 'critical')).toEqual([]);
  expect(results.violations.filter((violation) => violation.id === 'scrollable-region-focusable')).toEqual([]);
}

async function installClipboardProbe(page: Parameters<typeof setStoredTheme>[0]) {
  await page.context().grantPermissions(['clipboard-read', 'clipboard-write'], { origin: 'http://127.0.0.1:3118' });
  await page.addInitScript(() => {
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: {
        writeText: async (value: string) => {
          window.localStorage.setItem('coquic-playwright-copied', value);
        },
      },
    });
  });
}

test.describe('documentation routes', () => {
  test.describe.configure({ mode: 'default' });

  for (const doc of docs) {
    test(`${doc.href} retains title, heading, current desktop navigation, and document bounds`, async ({ page }, testInfo) => {
      test.skip(testInfo.project.name === 'mobile', 'The canonical route loop uses the desktop navigator.');
      await page.setViewportSize(designViewports.wide);
      await page.goto(doc.href);

      await expect(page).toHaveTitle(doc.title);
      await expect(page.locator('main h1')).toHaveCount(1);
      await expect(page.locator('aside[aria-label="Documentation pages"] a[aria-current="page"]')).toHaveAttribute('href', doc.href);
      await expectNoGlobalOverflow(page);
      await expectDocsAxe(page);
    });
  }

  test('the mobile drawer places content first and restores its trigger focus', async ({ page }) => {
    await page.setViewportSize(designViewports.phone320);
    await setStoredTheme(page, 'light');
    await page.goto('/docs/api/c-ffi-reference');

    const firstContent = page.locator('main article :is(h2, p)').first();
    await expect(firstContent).toBeVisible();
    expect((await firstContent.boundingBox())?.y).toBeLessThan(600);

    const trigger = page.getByRole('button', { name: 'Browse documentation' });
    await expect(trigger).toBeVisible();
    await expect(trigger).toHaveCSS('min-height', '44px');
    await trigger.click();

    const drawer = page.getByRole('dialog', { name: 'Documentation pages' });
    await expect(drawer).toBeVisible();
    await expect(drawer.getByRole('link')).toHaveCount(docItems.length);
    await expect(drawer.locator('a[aria-current="page"]')).toHaveAttribute('href', '/docs/api/c-ffi-reference');
    await page.keyboard.press('Escape');
    await expect(drawer).toBeHidden();
    await expect(trigger).toBeFocused();
  });

  test('the mobile drawer closes on its scrim and selected links', async ({ page }) => {
    await page.setViewportSize(designViewports.phone375);
    await page.goto('/docs');

    const trigger = page.getByRole('button', { name: 'Browse documentation' });
    await trigger.click();
    await page.locator('.ui-dialog__overlay').click({ position: { x: 2, y: 2 } });
    await expect(page.getByRole('dialog', { name: 'Documentation pages' })).toBeHidden();
    await expect(trigger).toBeFocused();

    await trigger.click();
    await page.getByRole('dialog', { name: 'Documentation pages' }).getByRole('link', { name: 'Public API' }).click();
    await expect(page).toHaveURL(/\/docs\/api\/public-api$/);
    await expect(page.getByRole('dialog', { name: 'Documentation pages' })).toBeHidden();
  });

  test('the C FFI reference keeps desktop navigation visible and preserves permalink and copy actions', async ({ page }) => {
    await page.setViewportSize(designViewports.wide);
    await installClipboardProbe(page);
    await page.goto('/docs/api/c-ffi-reference');

    const navigation = page.getByRole('navigation', { name: 'Documentation pages' });
    await navigation.getByRole('link', { name: 'C FFI Reference' }).focus();
    await expect(navigation.getByRole('link', { name: 'C FFI Reference' })).toBeFocused();
    await page.evaluate(() => window.scrollTo(0, 2400));
    await expect(navigation).toBeVisible();

    const heading = page.locator('.docs-function-heading .anchored-heading__title').first();
    const headingId = await heading.getAttribute('id');
    expect(headingId).toBeTruthy();
    const permalink = heading.locator('..').getByRole('link', { name: /Permalink to/ });
    await heading.hover();
    await expect(permalink).toBeVisible();
    await permalink.focus();
    await expect(permalink).toBeFocused();
    await permalink.click();
    await expect(page).toHaveURL(new RegExp(`#${headingId}$`));

    const codeBlock = page.locator('.editorial-code-block').first();
    const copyButton = codeBlock.getByRole('button');
    const copyStatus = codeBlock.getByRole('status');
    await expect(copyButton).toBeVisible();
    await copyButton.click();
    await expect(copyButton).toHaveAccessibleName('Code copied');
    await expect(copyStatus).toHaveText('Copied to clipboard.');
    const renderedCode = (await codeBlock.locator('code').innerText()).replace(/\s+/g, ' ').trim();
    await expect
      .poll(() => page.evaluate(() => window.localStorage.getItem('coquic-playwright-copied')))
      .toMatch(/\S/);
    const copiedCode = await page.evaluate(() => window.localStorage.getItem('coquic-playwright-copied'));
    expect(copiedCode?.replace(/\s+/g, ' ').trim()).toBe(renderedCode);
    await expectDocsAxe(page);
  });

  for (const theme of themes) {
    test(`the C FFI reference matches the ${theme} visual baseline`, async ({ page }) => {
      await setStoredTheme(page, theme);
      await page.goto('/docs/api/c-ffi-reference');
      await expect(page.locator('html')).toHaveAttribute('data-theme', theme);
      await expect(page.locator('main article')).toBeVisible();
      await prepareVisualSnapshot(page);
      await expect(page).toHaveScreenshot(`docs-api-c-ffi-reference-${theme}.png`, { fullPage: false });
    });
  }

  test('code remains a local scroll region on a narrow viewport', async ({ page }) => {
    await page.setViewportSize(designViewports.phone320);
    await setStoredTheme(page, 'dark');
    await page.goto('/docs/api/public-api');

    const codeRegion = page.locator('.editorial-code-scroll').first();
    await expect(codeRegion).toBeVisible();
    await expectLocalScrollRegion(page, '.editorial-code-scroll >> nth=0');
    await expectNoGlobalOverflow(page);
    await expectDocsAxe(page);
  });

  test('an invalid documentation route remains a 404', async ({ page }) => {
    const response = await page.goto('/docs/api/not-a-real-route');
    expect(response?.status()).toBe(404);
  });
});

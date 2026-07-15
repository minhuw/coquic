import { expect, test } from '@playwright/test';

import {
  designViewports,
  expectNoGlobalOverflow,
  expectNoSeriousAxeViolations,
  setStoredTheme,
  tabUntilFocused,
} from './helpers/design-system';

test('home portal exposes CoQUIC identity and real project entry points', async ({ page }) => {
  await page.goto('/');

  const home = page.locator('main.coquic-page');
  await expect(page.getByRole('heading', { level: 1 })).toHaveCount(1);
  await expect(page.getByRole('heading', { name: 'CoQUIC', exact: true, level: 1 })).toBeVisible();
  await expect(page.getByText('From Prompt to Packet.', { exact: true })).toBeVisible();

  for (const [name, href] of [
    ['Open Workbench', '/workbench'],
    ['Read the docs', '/docs'],
    ['View interop evidence', '/interop'],
  ] as const) {
    await expect(home.getByRole('link', { name, exact: true })).toHaveAttribute('href', href);
  }

  await expect(page.locator('meta[name="coquic-demo-marker"][content="coquic-wasm-demo-v1"]')).toHaveCount(1);
  await expect(page.locator('meta[name="coquic-home-marker"][content="coquic-demo-home-v1"]')).toHaveCount(1);
  await expect(home.getByRole('region', { name: 'Transfer scenario preview' })).toBeVisible();
  await expectNoGlobalOverflow(page);
  await expectNoSeriousAxeViolations(page, 'main');
});

test('home preview and task index expose their accessible project contracts', async ({ page }) => {
  await page.goto('/');

  const home = page.locator('main.coquic-page');
  const preview = home.getByRole('region', { name: 'Transfer scenario preview' });
  await expect(preview).toHaveAccessibleName('Transfer scenario preview');
  await expect(preview.getByRole('link', { name: 'Open scenario in Workbench', exact: true })).toHaveAttribute('href', '/workbench');

  for (const label of ['Client', 'Server', 'client to server', 'server to client', 'Initial', 'Handshake', '1-RTT']) {
    await expect(preview.getByText(label, { exact: true })).toBeVisible();
  }

  const taskIndex = home.getByRole('region', { name: 'Pick a project job' });
  await expect(taskIndex).toHaveAccessibleName('Pick a project job');
  for (const [title, href] of [
    ['Inspect protocol behavior', '/workbench'],
    ['Integrate the API', '/docs/api/integration'],
    ['Review evidence', '/duvet'],
    ['Browse development history', '/blog'],
    ['Monitor Steward', '/steward'],
  ] as const) {
    await expect(taskIndex.getByRole('link', { name: new RegExp(`^${title}`) })).toHaveAttribute('href', href);
  }

  await expectNoGlobalOverflow(page);
  await expectNoSeriousAxeViolations(page, 'main');
});

test('home remains readable without overflow under reduced motion and forced colors', async ({ page }) => {
  await page.emulateMedia({ forcedColors: 'active', reducedMotion: 'reduce' });

  for (const viewport of Object.values(designViewports)) {
    await page.setViewportSize(viewport);
    await page.goto('/');
    await expect(page.getByRole('heading', { name: 'CoQUIC', exact: true, level: 1 })).toBeVisible();
    await expect(page.getByRole('region', { name: 'Transfer scenario preview' })).toBeVisible();
    await expectNoGlobalOverflow(page);
    await expectNoSeriousAxeViolations(page, 'main');
  }
});

for (const [theme, expectedCanvas] of [
  ['light', 'rgb(250, 250, 248)'],
  ['dark', 'rgb(17, 18, 16)'],
] as const) {
  test(`home preserves ${theme} theme parity`, async ({ page }) => {
    await setStoredTheme(page, theme);
    await page.goto('/');

    await expect(page.locator('html')).toHaveAttribute('data-theme', theme);
    await expect.poll(() => page.evaluate(() => getComputedStyle(document.documentElement).colorScheme)).toBe(theme);
    await expect.poll(() => page.evaluate(() => getComputedStyle(document.body).backgroundColor)).toBe(expectedCanvas);
    await expect(page.getByRole('heading', { name: 'CoQUIC', exact: true, level: 1 })).toBeVisible();
    await expect(page.getByRole('region', { name: 'Transfer scenario preview' })).toBeVisible();
    await expect(page.getByRole('region', { name: 'Pick a project job' })).toBeVisible();
    await expectNoSeriousAxeViolations(page, 'main');
  });
}

test('home actions activate with keyboard-only focus and Enter', async ({ page }) => {
  for (const [name, href] of [
    ['Open Workbench', '/workbench'],
    ['Read the docs', '/docs'],
    ['View interop evidence', '/interop'],
  ] as const) {
    await page.goto('/');
    const link = page.locator('main.coquic-page').getByRole('link', { name, exact: true });
    await tabUntilFocused(page, link);
    await expect(link).toBeFocused();
    await link.press('Enter');
    await expect(page).toHaveURL(href);
  }
});

test('home remains usable at 200 percent page scale', async ({ page }) => {
  await page.goto('/');
  const client = await page.context().newCDPSession(page);
  await client.send('Emulation.setPageScaleFactor', { pageScaleFactor: 2 });

  await expect.poll(() => page.evaluate(() => window.visualViewport?.scale)).toBe(2);
  await expect(page.getByRole('heading', { name: 'CoQUIC', exact: true, level: 1 })).toBeVisible();
  await expect(page.getByRole('link', { name: 'Open Workbench', exact: true })).toBeVisible();
  await expect(page.getByRole('region', { name: 'Transfer scenario preview' })).toBeVisible();
  await expect(page.getByRole('region', { name: 'Pick a project job' })).toBeVisible();
  await expectNoGlobalOverflow(page);
  await expectNoSeriousAxeViolations(page, 'main');
});

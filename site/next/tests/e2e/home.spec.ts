import { expect, test } from '@playwright/test';

import {
  designViewports,
  expectNoGlobalOverflow,
  expectNoSeriousAxeViolations,
  setStoredTheme,
  tabUntilFocused,
} from './helpers/design-system';

test('home presents CoQUIC with Steward as its primary destination', async ({ page }) => {
  await page.goto('/');

  const home = page.locator('main.coquic-page');
  await expect(page.getByRole('heading', { level: 1 })).toHaveCount(1);
  await expect(page.getByRole('heading', { name: 'CoQUIC', exact: true, level: 1 })).toBeVisible();
  await expect(page.getByText('From Prompt to Packet.', { exact: true })).toBeVisible();
  await expect(home.getByRole('link', { name: 'Open Steward', exact: true })).toHaveAttribute('href', '/steward');

  await expect(page.locator('meta[name="coquic-demo-marker"][content="coquic-wasm-demo-v1"]')).toHaveCount(1);
  await expect(page.locator('meta[name="coquic-home-marker"][content="coquic-demo-home-v1"]')).toHaveCount(1);
  await expect(home.locator('.home-facts, .home-actions, .home-open')).toHaveCount(0);
  await expect(home.getByRole('region', { name: 'Transfer scenario preview' })).toHaveCount(0);
  await expectNoGlobalOverflow(page);
  await expectNoSeriousAxeViolations(page, 'main');
});

test('home uses a consistent wide composition on large screens', async ({ page }) => {
  await page.setViewportSize({ width: 1920, height: 1000 });
  await page.goto('/');

  const layout = await page.evaluate(() => {
    const selectors = [
      '.home-hero-inner',
      '.home-evidence > .container-wide',
      '.home-tools > .container-wide',
    ];
    const bandWidths = selectors.map((selector) => {
      const element = document.querySelector<HTMLElement>(selector);
      if (!element) throw new Error(`Missing homepage band: ${selector}`);
      return element.getBoundingClientRect().width;
    });
    const copy = document.querySelector<HTMLElement>('.home-hero-copy')?.getBoundingClientRect();
    const steward = document.querySelector<HTMLElement>('.home-steward-feature')?.getBoundingClientRect();
    if (!copy || !steward) throw new Error('Missing homepage hero column');

    return {
      bandWidths,
      copyRight: copy.right,
      stewardLeft: steward.left,
    };
  });

  expect(Math.min(...layout.bandWidths)).toBeGreaterThan(1500);
  expect(Math.max(...layout.bandWidths) - Math.min(...layout.bandWidths)).toBeLessThanOrEqual(1);
  expect(layout.stewardLeft).toBeGreaterThan(layout.copyRight);
  await expectNoGlobalOverflow(page);
});

test('home orders evidence before its four project tools', async ({ page }) => {
  await page.goto('/');

  const home = page.locator('main.coquic-page');
  const bands = home.locator(':scope > section');
  await expect(bands).toHaveCount(3);
  await expect(bands.nth(0)).toHaveClass(/home-hero/);
  await expect(bands.nth(1)).toHaveClass(/home-evidence/);
  await expect(bands.nth(2)).toHaveClass(/home-tools/);

  const evidence = home.getByRole('region', { name: 'Evidence', exact: true });
  for (const [name, description, href] of [
    ['Performance', 'Throughput and request-rate benchmarks.', '/performance'],
    ['Interop', 'Peer and testcase results.', '/interop'],
    ['Coverage', 'Source coverage by path.', '/coverage'],
    ['Duvet', 'RFC requirements mapped to source and tests.', '/duvet'],
  ] as const) {
    const link = evidence.getByRole('link', { name: new RegExp(`^${name}`) });
    await expect(link).toHaveAttribute('href', href);
    await expect(link.getByText(description, { exact: true })).toBeVisible();
  }

  const tools = home.getByRole('region', { name: 'Tools', exact: true });
  for (const [name, description, href] of [
    ['Workbench', 'Packets, streams, and recovery.', '/workbench'],
    ['API', 'Sans-I/O integration guide.', '/docs/api/integration'],
    ['Ask', 'QUIC answers with RFC citations.', '/qa'],
    ['Dataset', 'Public Codex transcripts.', '/transcript'],
  ] as const) {
    const link = tools.getByRole('link', { name: new RegExp(`^${name}`) });
    await expect(link).toHaveAttribute('href', href);
    await expect(link.getByText(description, { exact: true })).toBeVisible();
  }

  await expect(evidence.locator('.home-index-links a')).toHaveCount(4);
  await expect(tools.locator('.home-index-links a')).toHaveCount(4);
  await expect(evidence.locator('.home-index-art')).toHaveCount(4);
  await expect(tools.locator('.home-index-art')).toHaveCount(4);
  for (const variant of ['performance', 'interop', 'coverage', 'duvet', 'workbench', 'api', 'ask', 'dataset']) {
    await expect(home.locator(`.home-index-art--${variant}`)).toHaveCount(1);
  }
  const artworkDimensions = await home.locator('.home-index-art').evaluateAll((artworks) =>
    artworks.map((artwork) => {
      const { width, height } = artwork.getBoundingClientRect();
      return { width, height };
    }),
  );
  for (const { width, height } of artworkDimensions) {
    expect(width).toBeGreaterThan(0);
    expect(Math.abs(width - height)).toBeLessThanOrEqual(1);
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
    await expect(page.getByRole('region', { name: 'Evidence', exact: true })).toBeVisible();
    await expect(page.getByRole('region', { name: 'Tools', exact: true })).toBeVisible();
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
    await expect(page.getByRole('region', { name: 'Evidence', exact: true })).toBeVisible();
    await expect(page.getByRole('region', { name: 'Tools', exact: true })).toBeVisible();
    await expectNoSeriousAxeViolations(page, 'main');
  });
}

test('home destinations activate with keyboard-only focus and Enter', async ({ page }) => {
  for (const [name, href] of [
    ['Open Steward', '/steward'],
    ['Performance', '/performance'],
    ['Workbench', '/workbench'],
  ] as const) {
    await page.goto('/');
    const link = page.locator('main.coquic-page').getByRole('link', { name: new RegExp(`^${name}`) });
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
  await expect(page.getByRole('link', { name: 'Open Steward', exact: true })).toBeVisible();
  await expect(page.getByRole('region', { name: 'Tools', exact: true })).toBeVisible();
  await expectNoGlobalOverflow(page);
  await expectNoSeriousAxeViolations(page, 'main');
});

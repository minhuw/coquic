import { expect, test } from '@playwright/test';

import { expectNoGlobalOverflow, setStoredTheme, waitForVisualAssets } from './helpers/design-system';

const themes = ['light', 'dark'] as const;

test.use({ launchOptions: { args: ['--disable-gpu'] } });

function trackThirdPartyFontRequests(page: Parameters<typeof setStoredTheme>[0]) {
  const requests: string[] = [];
  page.on('request', (request) => {
    const url = new URL(request.url());
    const isLocal = url.hostname === '127.0.0.1' || url.hostname === 'localhost';
    if ((!isLocal && request.resourceType() === 'font') || /fonts\.(?:googleapis|gstatic)\.com/i.test(url.hostname)) {
      requests.push(request.url());
    }
  });
  return requests;
}

async function prepareVisualCapture(page: Parameters<typeof setStoredTheme>[0]) {
  await waitForVisualAssets(page);
}

test.describe('content primitive compositions', () => {
  for (const theme of themes) {
    test(`prose, table, and server code stay bounded in ${theme}`, async ({ page }) => {
      const thirdPartyFontRequests = trackThirdPartyFontRequests(page);
      await setStoredTheme(page, theme);
      await page.goto('/docs/api/c-ffi-reference');

      await expect(page.locator('html')).toHaveAttribute('data-theme', theme);
      await expect(page.locator('[data-prose-variant="editorial"]')).toHaveCount(1);
      await expect(page.locator('[data-editorial-code-block="true"]')).not.toHaveCount(0);
      const tableRegions = page.locator('[data-editorial-table-region="true"]');
      if (await tableRegions.count()) await expect(tableRegions.first()).toBeVisible();
      await expectNoGlobalOverflow(page);
      await prepareVisualCapture(page);
      await expect(page).toHaveScreenshot(`prose-table-code-${theme}.png`, { fullPage: false });
      expect(thirdPartyFontRequests).toEqual([]);
    });

  }
});

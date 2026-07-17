import { expect, test } from '@playwright/test';

import { setStoredTheme } from './helpers/design-system';

for (const theme of ['light', 'dark'] as const) {
  test(`${theme} shared shell foundation`, async ({ page }) => {
    await setStoredTheme(page, theme);
    await page.goto('/');
    await expect(page.locator('html')).toHaveAttribute('data-theme', theme);
    await expect(page.locator('[data-shell-control="theme-toggle"]:visible')).toHaveAttribute(
      'aria-pressed',
      theme === 'dark' ? 'true' : 'false',
    );
    await page.evaluate(() => document.fonts.ready);

    await expect(page).toHaveScreenshot(`foundation-${theme}.png`, {
      animations: 'disabled',
      caret: 'hide',
      fullPage: false,
      scale: 'css',
    });
  });
}

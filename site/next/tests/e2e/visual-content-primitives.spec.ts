import { expect, test } from '@playwright/test';

import { expectNoGlobalOverflow, setStoredTheme } from './helpers/design-system';

const themes = ['light', 'dark'] as const;
const taskRoute = '/steward/tasks/task-20260713115945-a1b2c3d4';

test.describe('content primitive compositions', () => {
  for (const theme of themes) {
    test(`prose, table, and server code stay bounded in ${theme}`, async ({ page }) => {
      await setStoredTheme(page, theme);
      await page.goto('/docs/api/c-ffi-reference');

      await expect(page.locator('html')).toHaveAttribute('data-theme', theme);
      await expect(page.locator('[data-prose-variant="editorial"]')).toHaveCount(1);
      await expect(page.locator('[data-editorial-code-block="true"]')).not.toHaveCount(0);
      const tableRegions = page.locator('[data-editorial-table-region="true"]');
      if (await tableRegions.count()) await expect(tableRegions.first()).toBeVisible();
      await expectNoGlobalOverflow(page);
      await expect(page).toHaveScreenshot(`prose-table-code-${theme}.png`, { fullPage: false });
    });

    test(`evidence transcript and diff stay bounded in ${theme}`, async ({ page }) => {
      await setStoredTheme(page, theme);
      await page.goto(taskRoute);

      await expect(page.locator('html')).toHaveAttribute('data-theme', theme);
      const transcriptTab = page.getByRole('tab', { name: 'Transcript' }).first();
      await expect(transcriptTab).toBeVisible();
      await transcriptTab.click();
      await expect(page.locator('.evidence-root')).not.toHaveCount(0);
      await expect(page.locator('.evidence-message, .evidence-disclosure')).not.toHaveCount(0);
      await expectNoGlobalOverflow(page);
      await expect(page).toHaveScreenshot(`evidence-transcript-${theme}.png`, { fullPage: false });

      const patchTab = page.getByRole('tab', { name: 'Patch' }).first();
      await patchTab.click();
      await expect(page.locator('[data-evidence-code-block="true"]')).not.toHaveCount(0);
      await expect(page.locator('.diff-split, .diff-unified')).not.toHaveCount(0);
      await expectNoGlobalOverflow(page);
      await expect(page).toHaveScreenshot(`evidence-diff-${theme}.png`, { fullPage: false });
    });
  }
});

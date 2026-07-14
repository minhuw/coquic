import { expect, test } from '@playwright/test';

import { setStoredTheme, tabUntilFocused } from './helpers/design-system';

test.describe('desktop shell behavior', () => {
  test.skip(({ isMobile }) => isMobile, 'Shell interaction characterization runs in the desktop project.');

  test('home logo navigates and active destinations expose aria-current', async ({ page }) => {
    await page.goto('/docs');
    await expect(page.getByRole('link', { name: 'Docs' })).toHaveAttribute('aria-current', 'page');
    const home = page.getByRole('link', { name: 'Home' });
    await tabUntilFocused(page, home);
    await home.press('Enter');
    await expect(page).toHaveURL('/');
    await expect(page.getByRole('link', { name: 'Home' })).toHaveAttribute('aria-current', 'page');
  });

  test('theme choice persists across navigation and reload', async ({ page }) => {
    await setStoredTheme(page, 'light');
    await page.goto('/');
    await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
    await page.getByRole('button', { name: 'Switch to dark mode' }).click();
    await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
    await expect.poll(() => page.evaluate(() => localStorage.getItem('coquic-theme'))).toBe('dark');
    await page.getByRole('link', { name: 'Docs' }).click();
    await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
    await page.reload();
    await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  });

  test('keyboard shortcuts filter, select, navigate, and dismiss search', async ({ page }) => {
    await page.goto('/');
    await page.keyboard.press('Control+k');
    const dialog = page.getByRole('dialog', { name: 'Site search' });
    const input = page.getByRole('searchbox', { name: 'Search CoQUIC' });
    await expect(dialog).toBeVisible();
    await input.fill('coverage');
    await expect(page.getByRole('option').filter({ hasText: 'Coverage Report' })).toBeVisible();
    await page.keyboard.press('Escape');
    await expect(dialog).toHaveCount(0);

    await page.keyboard.press('Meta+k');
    await expect(dialog).toBeVisible();
    await input.fill('protocol workbench');
    const firstResult = page.getByRole('option').first();
    await expect(firstResult).toContainText('Protocol Workbench');
    await input.press('ArrowDown');
    await expect(firstResult).toHaveAttribute('aria-selected', 'false');
    await input.press('ArrowUp');
    await expect(firstResult).toHaveAttribute('aria-selected', 'true');
    await input.press('Enter');
    await expect(page).toHaveURL('/workbench');
  });

  for (const disclosure of ['Benchmark', 'Development']) {
    test(`${disclosure} disclosure closes on Escape and outside pointer`, async ({ page }) => {
      await page.goto('/');
      const trigger = page.getByRole('button', { name: disclosure });
      await trigger.click();
      await expect(trigger).toHaveAttribute('aria-expanded', 'true');
      await trigger.press('Escape');
      await expect(trigger).toHaveAttribute('aria-expanded', 'false');
      await trigger.click();
      await expect(trigger).toHaveAttribute('aria-expanded', 'true');
      await page.getByRole('heading', { level: 1 }).click();
      await expect(trigger).toHaveAttribute('aria-expanded', 'false');
    });
  }
});

test.fixme('plan 003 provides complete mobile menu access', async ({ page }) => {
  await page.setViewportSize({ width: 320, height: 800 });
  await page.goto('/');
  await expect(page.getByRole('navigation', { name: 'Demo views' }).getByRole('link')).toHaveCount(11);
});

test.fixme('plan 003 restores search focus after dismissal', async ({ page }) => {
  await page.goto('/');
  const trigger = page.getByRole('button', { name: 'Search' });
  await trigger.click();
  await page.keyboard.press('Escape');
  await expect(trigger).toBeFocused();
});

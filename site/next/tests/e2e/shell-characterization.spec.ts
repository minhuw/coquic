import { expect, test } from '@playwright/test';

import { expectNoSeriousAxeViolations, setStoredTheme, tabUntilFocused } from './helpers/design-system';

test.describe('desktop shell behavior', () => {
  test.skip(({ isMobile }) => isMobile, 'Shell interaction characterization runs in the desktop project.');

  test('home logo navigates and active destinations expose aria-current', async ({ page }) => {
    await page.goto('/docs');
    await expect(page.getByRole('link', { name: 'Docs' })).toHaveAttribute('aria-current', 'page');
    const home = page.getByRole('link', { name: 'Home', exact: true });
    await tabUntilFocused(page, home);
    await home.press('Enter');
    await expect(page).toHaveURL('/');
    await expect(page.getByRole('link', { name: 'Home', exact: true })).toHaveAttribute('aria-current', 'page');
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
    await expect(page.getByRole('link').filter({ hasText: 'Coverage Report' })).toBeVisible();
    await page.keyboard.press('Escape');
    await expect(dialog).toHaveCount(0);

    await page.keyboard.press('Meta+k');
    await expect(dialog).toBeVisible();
    await input.fill('protocol workbench');
    const firstResult = page.getByRole('link').filter({ hasText: 'Protocol Workbench' }).first();
    await expect(firstResult).toContainText('Protocol Workbench');
    await input.press('ArrowDown');
    await expect(firstResult).not.toHaveAttribute('data-active', 'true');
    await input.press('ArrowUp');
    await expect(firstResult).toHaveAttribute('data-active', 'true');
    await input.press('Enter');
    await expect(page).toHaveURL('/workbench');
  });

  test('search clears and reports no matches', async ({ page }) => {
    await page.goto('/');
    await page.getByRole('button', { name: 'Search' }).click();
    const input = page.getByRole('searchbox', { name: 'Search CoQUIC' });
    await input.fill('zzzzqv blorpt');
    await expect(page.getByText('No matches')).toBeVisible();
    await expect(page.getByRole('status')).toHaveText('0 results');
    await input.fill('coverage');
    await page.getByRole('button', { name: 'Clear search' }).click();
    await expect(input).toHaveValue('');
    await expect(page.getByText('Suggested destinations')).toBeVisible();
  });

  test('open search has no serious accessibility violations', async ({ page }) => {
    await page.goto('/');
    await page.getByRole('button', { name: 'Search' }).click();
    await expectNoSeriousAxeViolations(page);
    await page.getByRole('searchbox', { name: 'Search CoQUIC' }).fill('coverage');
    await expectNoSeriousAxeViolations(page);
  });

  for (const disclosure of ['Evidence', 'Project']) {
    test(`${disclosure} disclosure closes on Escape, outside pointer, and link selection`, async ({ page }) => {
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
      await expect(trigger).toBeFocused();
      await trigger.click();
      await page.getByRole('link', { name: disclosure === 'Evidence' ? 'Coverage' : 'Blog' }).click();
      await expect(page).toHaveURL(disclosure === 'Evidence' ? '/coverage' : '/blog');
    });
  }
});

test('system theme changes update the document without persistence', async ({ page }) => {
  await page.emulateMedia({ colorScheme: 'light' });
  await page.addInitScript(() => localStorage.removeItem('coquic-theme'));
  await page.goto('/');
  await page.emulateMedia({ colorScheme: 'dark' });
  await expect.poll(() => page.locator('html').getAttribute('data-theme')).toBe('dark');
  await expect.poll(() => page.evaluate(() => getComputedStyle(document.documentElement).colorScheme)).toBe('dark');
  await expect.poll(() => page.evaluate(() => localStorage.getItem('coquic-theme'))).toBeNull();
});

test('theme script sets the first-frame system and saved themes', async ({ page }) => {
  await page.emulateMedia({ colorScheme: 'dark' });
  await page.addInitScript(() => {
    localStorage.removeItem('coquic-theme');
    (window as typeof window & { __coquicFirstFrame: Promise<unknown> }).__coquicFirstFrame = new Promise((resolve) => requestAnimationFrame(() => resolve({ theme: document.documentElement.dataset.theme, colorScheme: getComputedStyle(document.documentElement).colorScheme })));
  });
  await page.goto('/');
  await expect.poll(() => page.evaluate(() => (window as typeof window & { __coquicFirstFrame: Promise<unknown> }).__coquicFirstFrame)).toEqual({ theme: 'dark', colorScheme: 'dark' });

  await page.emulateMedia({ colorScheme: 'dark' });
  await page.addInitScript(() => {
    localStorage.setItem('coquic-theme', 'light');
    (window as typeof window & { __coquicFirstFrame: Promise<unknown> }).__coquicFirstFrame = new Promise((resolve) => requestAnimationFrame(() => resolve({ theme: document.documentElement.dataset.theme, colorScheme: getComputedStyle(document.documentElement).colorScheme })));
  });
  await page.reload();
  await expect.poll(() => page.evaluate(() => (window as typeof window & { __coquicFirstFrame: Promise<unknown> }).__coquicFirstFrame)).toEqual({ theme: 'light', colorScheme: 'light' });
});

test('plan 003 provides complete mobile menu access', async ({ page }) => {
  await page.setViewportSize({ width: 320, height: 800 });
  await page.goto('/');
  await page.getByRole('button', { name: 'Open menu' }).click();
  await expect(page.getByRole('dialog', { name: 'CoQUIC navigation' }).getByRole('link')).toHaveCount(12);
});

test('plan 003 restores search focus after dismissal', async ({ page }) => {
  await page.goto('/');
  const trigger = page.getByRole('button', { name: 'Search' });
  await trigger.click();
  await page.keyboard.press('Escape');
  await expect(trigger).toBeFocused();
});

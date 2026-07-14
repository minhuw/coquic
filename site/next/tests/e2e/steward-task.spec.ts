import { expect, test } from '@playwright/test';

import {
  designViewports,
  expectLocalScrollRegion,
  expectNoGlobalOverflow,
  expectNoSeriousAxeViolations,
  setStoredTheme,
} from './helpers/design-system';

const taskRoute = '/steward/tasks/task-20260713115945-a1b2c3d4';

test.describe('Steward task evidence detail', () => {
  test('keeps the route main as the sole landmark and leads with current evidence', async ({ page }) => {
    await page.goto(taskRoute);

    await expect(page.locator('main.coquic-page')).toHaveCount(1);
    await expect(page.locator('main main')).toHaveCount(0);
    await expect(page.getByRole('heading', { name: 'Implement dashboard contract', level: 1 })).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Current iteration', level: 2 })).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Implementation plan', level: 2 })).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Attempts', level: 2 })).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Timeline', level: 2 })).toBeVisible();
    await expect(page.getByText('Current conclusion')).toBeVisible();
    await expect(page.getByRole('list', { name: 'Task pipeline stages and feedback loops' }).getByText('Code Generation', { exact: true })).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Worktree ready', level: 3 })).toBeVisible();
  });

  test('keeps task evidence within the viewport at mobile and exposes the complete ordered flow', async ({ page }) => {
    for (const viewport of [designViewports.phone320, designViewports.phone375, designViewports.phone414]) {
      await page.setViewportSize(viewport);
      await page.goto(taskRoute);
      await expectNoGlobalOverflow(page);
      await expect(page.locator('.pipeline-graph')).toBeHidden();
      await expect(page.getByRole('list', { name: 'Task pipeline stages and feedback loops' })).toBeVisible();
      await expect(page.getByText('Integration', { exact: true }).last()).toBeVisible();
      await expect(page.getByRole('link', { name: /Back to Steward/ })).toBeVisible();
    }
  });

  test('keeps the bounded visual graph and text equivalent at the tablet breakpoint', async ({ page }) => {
    await page.setViewportSize(designViewports.tablet);
    await page.goto(taskRoute);
    const graph = page.locator('.pipeline-graph');
    await expect(graph).toBeVisible();
    await expectLocalScrollRegion(page, '.task-timeline');

    const geometry = await graph.evaluate((element) => ({
      clientWidth: element.clientWidth,
      right: element.getBoundingClientRect().right,
      scrollWidth: element.scrollWidth,
      viewport: window.innerWidth,
    }));
    expect(geometry.right).toBeLessThanOrEqual(geometry.viewport + 1);
    expect(geometry.scrollWidth).toBeLessThanOrEqual(geometry.clientWidth + 1);
    await expect(page.getByRole('list', { name: 'Task pipeline stages and feedback loops' })).toBeVisible();
  });

  test('preserves keyboard tabs, disclosures, side-by-side diff, and focus return', async ({ page }) => {
    await page.goto(taskRoute);
    const attempt = page.getByRole('button', { name: /Initial attempt/ });
    await expect(attempt).toHaveAttribute('aria-expanded', 'true');
    await attempt.press('Enter');
    await expect(attempt).toHaveAttribute('aria-expanded', 'false');
    await attempt.press('Enter');

    const transcriptTab = page.getByRole('tab', { name: 'Transcript' });
    await transcriptTab.focus();
    await transcriptTab.press('ArrowRight');
    await expect(page.getByRole('tab', { name: 'Patch' })).toHaveAttribute('aria-selected', 'true');
    const openDiff = page.getByRole('button', { name: 'Open side-by-side diff' });
    await openDiff.focus();
    await openDiff.press('Enter');
    await expect(page.getByRole('dialog', { name: 'Patch side-by-side' })).toBeVisible();
    await page.keyboard.press('Escape');
    await expect(page.getByRole('dialog')).toHaveCount(0);
    await expect(openDiff).toBeFocused();
  });

  test('keeps themes, reduced motion, local scroll, and serious accessibility checks clean', async ({ page }) => {
    await setStoredTheme(page, 'dark');
    await page.goto(taskRoute);
    await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
    await page.emulateMedia({ reducedMotion: 'reduce' });
    await expectNoGlobalOverflow(page);
    await expectLocalScrollRegion(page, '.task-timeline');
    await expectNoSeriousAxeViolations(page, 'main');

    await page.emulateMedia({ forcedColors: 'active', reducedMotion: 'reduce' });
    expect(await page.evaluate(() => window.matchMedia('(forced-colors: active)').matches)).toBe(true);
    await expect(page.locator('.task-status').first()).toHaveCSS('forced-color-adjust', 'none');
    await expect(page.getByText('Current conclusion')).toBeVisible();
  });

  test('keeps invalid task ids as 404 responses', async ({ page }) => {
    const response = await page.goto('/steward/tasks/not-a-task-id');
    expect(response?.status()).toBe(404);
  });
});

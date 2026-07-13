import { expect, test } from '@playwright/test';

test.describe('Steward public monitor', () => {
  test('renders the active overview and runtime state', async ({ page }) => {
    await page.goto('/steward');
    await expect(page.getByRole('heading', { name: 'CoQUIC Steward' })).toBeVisible();
    await expect(page.getByText('Monitor')).toBeVisible();
    await expect(page.getByRole('region', { name: 'Steward runtime status' }).getByText('Live', { exact: true })).toBeVisible();
    await expect(page.getByText('Daemon')).toBeVisible();
  });

  test('switches between task and signal views', async ({ page }) => {
    await page.goto('/steward');
    await page.getByRole('tab', { name: /Tasks/ }).click();
    await expect(page.getByRole('link', { name: 'Implement dashboard contract', exact: true })).toBeVisible();
    await page.getByRole('tab', { name: /Signals/ }).click();
    await expect(page.getByText('Contract checks are running')).toBeVisible();
    await expect(page.getByRole('tablist', { name: 'Signal providers' }).getByRole('tab', { name: /github-actions:ci/ })).toBeVisible();
  });

  test('renders planner history and a retained task detail', async ({ page }) => {
    await page.goto('/steward/planner');
    await expect(page.getByRole('heading', { name: 'Planner history' })).toBeVisible();
    await expect(page.getByText('planner-task-20260713115600-a1b2c3d4')).toBeVisible();

    await page.goto('/steward/tasks/task-20260713115945-a1b2c3d4');
    await expect(page.getByRole('heading', { name: 'Implement dashboard contract' })).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Worktree ready', level: 3 })).toBeVisible();
    await expect(page.getByText('Timeline')).toBeVisible();
  });

  test('keeps operational controls inside the viewport', async ({ page }) => {
    await page.goto('/steward');
    const overflow = await page.evaluate(() => ({
      document: document.documentElement.scrollWidth,
      viewport: window.innerWidth,
      controls: [...document.querySelectorAll('.steward-mirror-shell button, .steward-mirror-shell a, .steward-mirror-shell input')]
        .filter((element) => element.getBoundingClientRect().right > window.innerWidth + 1)
        .map((element) => element.textContent?.trim() || element.getAttribute('aria-label') || element.tagName),
    }));
    expect(overflow.document).toBeLessThanOrEqual(overflow.viewport + 1);
    expect(overflow.controls).toEqual([]);
  });
});
